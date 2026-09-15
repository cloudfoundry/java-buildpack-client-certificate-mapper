/*
 * Copyright 2017-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.router;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.LongAdder;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A bounded, lock-free cache of {@link ParsedXfcc} bundles based on a generational eviction strategy.
 *
 * <p>Two generations of {@link ConcurrentHashMap} are maintained: {@code currentGen} and
 * {@code prevGen}. Lookups check current first, then previous. When the current generation
 * reaches {@code maxGenSize}, it is promoted to previous (the old previous is discarded) and
 * a fresh current generation starts. This keeps memory bounded at approximately
 * {@code 2 * maxGenSize} entries while avoiding any locking on the read path.
 *
 * <p><b>What is cached.</b> The cache value is a {@link ParsedXfcc} bundle: the parsed
 * {@link XfccEntry}, the decoded {@link java.security.cert.X509Certificate}, and, when present,
 * the parsed {@link CfSubjectDn}. Caching the full bundle rather than only the certificate lets a
 * repeat of the same header skip {@code XfccEntry} one-pass parsing (~1.3 KB scan per request) and
 * CF subject DN parsing, both of which showed up in profiler traces even after X.509 parsing was
 * already being cached.
 *
 * <p><b>Concurrent parse deduplication.</b> {@link #getOrCompute(String, ParsedXfccSupplier)} uses
 * {@link ConcurrentHashMap#computeIfAbsent(Object, java.util.function.Function)} to serialize the
 * miss path per key. When many threads race with the same cache-cold key (e.g. a burst of requests
 * carrying the same XFCC header), only one thread invokes the supplier — the others wait briefly on
 * the bucket lock and receive the computed result — avoiding a thundering-herd parse spike.
 * Different keys never block each other. Prefer {@code getOrCompute} over the raw {@link #get} /
 * {@link #put} pair on hot paths.
 *
 * <p><b>Why not key by the raw certificate string.</b> Using the full ~1.3 KB {@code Cert=} (or raw
 * header) value directly as the map key was measured to burn most of the cache's benefit: because
 * each request produces a fresh {@code String} instance from XFCC substring parsing,
 * {@link String#hashCode()} cannot be reused across requests and traverses the whole key on every
 * lookup, and a hit also requires a full-length {@link String#equals(Object)}. JMH measurement on
 * JDK 25 (single-threaded, {@code AverageTime}, 5+5 iterations × 2 forks):
 * <pre>
 *   parse the cert every call (no cache):            ~3620 ns/op
 *   cache hit keyed by the raw ~1.3 KB cert string:  ~1890 ns/op  (only 1.9x vs no cache)
 *   cache hit keyed by 64-char SHA-256 hex digest:    ~130 ns/op  (28x vs no cache)
 * </pre>
 * Deriving a short digest recovers ~14.6x of the per-hit cost and — under real concurrent load —
 * removes the compounded per-request CPU that made a raw-key cache measurably worse than no cache
 * at all in field measurements.
 *
 * <p><b>Memory budget.</b> Keys are 64-character SHA-256 hex digests derived from the raw header
 * value the entry was parsed from. Deriving the key ensures only a request carrying the actual
 * header can produce a hit, and keeps {@link String#hashCode()} and {@link String#equals(Object)}
 * on the cache key cheap on every lookup. Note that the digest is taken over the header string as
 * received — the URL-encoded PEM or base64 DER — not over the decoded DER bytes, so the key
 * intentionally differs from the Envoy XFCC {@code Hash=} field (which is defined as SHA-256 of the
 * DER). This is fine for cache identity (same header value produces the same key) but means the two
 * hashes are not cross-comparable. With the default generation size of 128, the cache holds at most
 * ~256 {@link ParsedXfcc} bundles plus ~16 KB of key strings.
 * If this is a concern, disable caching via the
 * {@code org.cloudfoundry.router.certificate.cache.enabled} system property.
 *
 * <p><b>Security note.</b> Cached entries are not expiry-checked on retrieval. The filter
 * does not validate certificate validity on cache hits (nor on misses), consistent with
 * behaviour before caching was introduced. Callers that require expiry enforcement should
 * check {@code X509Certificate.checkValidity()} on the mapped attribute themselves.
 *
 * <p>The implementation is safe for concurrent use. Under a simultaneous rotation race,
 * at most a few entries may be re-parsed once — no data is corrupted.
 *
 * <p><b>Logging.</b> Every lookup logs a hit or a miss at {@code FINE}. Generation rotation logs
 * a {@link #statistics() statistics} snapshot: the first rotation at {@code INFO}, because that is
 * the point at which the cache reaches capacity and starts evicting, and every rotation after it at
 * {@code FINE}, so traffic with mostly unique certificates cannot flood the log. Rotation is used as
 * the reporting interval because it needs no timer and no clock reads on the request path.
 *
 * <p>Use {@link #get(String)} and {@link #put(String, ParsedXfcc)} as the only entry
 * points so the implementation can be replaced without touching call sites.
 */
public final class CertificateCache {

    private static final Logger LOGGER = Logger.getLogger(CertificateCache.class.getName());

    private final int maxGenSize;

    private final LongAdder hits = new LongAdder();

    private final LongAdder misses = new LongAdder();

    private final LongAdder rotations = new LongAdder();

    /** Guards the one-off {@code INFO} log for the rotation that first takes the cache to capacity. */
    private final AtomicBoolean capacityReached = new AtomicBoolean();

    private volatile ConcurrentHashMap<String, ParsedXfcc> currentGen;
    private volatile ConcurrentHashMap<String, ParsedXfcc> prevGen;

    public CertificateCache(int maxGenSize) {
        this.maxGenSize = maxGenSize;
        this.currentGen = new ConcurrentHashMap<>();
        this.prevGen = new ConcurrentHashMap<>();
    }

    /** Returns the cached bundle for {@code key}, or {@code null} if not present. */
    public ParsedXfcc get(String key) {
        ParsedXfcc value = currentGen.get(key);
        if (value == null) {
            value = prevGen.get(key);
        }
        if (value == null) {
            recordMiss();
            return null;
        }
        recordHit();
        return value;
    }

    /**
     * Returns the cached bundle for {@code key} without recording a hit or a miss, or {@code null}
     * if not present. Intended for callers that need to short-circuit expensive work (such as
     * parsing the raw header into an {@link XfccEntry}) before they know whether the entry is even
     * cache-eligible; such a caller records the miss itself once it decides to call
     * {@link #getOrCompute}, so this method must stay silent to avoid double-counting.
     */
    ParsedXfcc peek(String key) {
        ParsedXfcc value = currentGen.get(key);
        if (value == null) {
            value = prevGen.get(key);
        }
        if (value != null) {
            recordHit();
        }
        return value;
    }

    /** Stores {@code value} under {@code key}, rotating generations if the current one is full. */
    public void put(String key, ParsedXfcc value) {
        rotateIfFull();
        currentGen.put(key, value);
    }

    /**
     * Returns the cached bundle for {@code key}, invoking {@code supplier} exactly once per key
     * on a miss even when many threads race with the same key. This solves the cache-stampede
     * ("thundering herd") case where a burst of concurrent requests carrying the same XFCC header
     * would otherwise each parse the same certificate.
     *
     * <p>Serialization is achieved by delegating the miss path to
     * {@link ConcurrentHashMap#computeIfAbsent(Object, java.util.function.Function)} on the current
     * generation. That call locks only the target bucket while the mapping function runs, so
     * concurrent callers with different keys never block each other. Callers with the same key have
     * at most one thread actually parse; the rest wait briefly and receive the computed result.
     *
     * <p>If {@code supplier} throws, the exception is propagated to the caller and no entry is
     * stored; the next request retries the parse.
     */
    public ParsedXfcc getOrCompute(String key, ParsedXfccSupplier supplier)
            throws CertificateException, IOException {
        // Fast path: no lock, no wait for concurrent parsers.
        ParsedXfcc value = currentGen.get(key);
        if (value != null) {
            recordHit();
            return value;
        }
        value = prevGen.get(key);
        if (value != null) {
            recordHit();
            return value;
        }
        // Rotate before entering computeIfAbsent — the mapping function must not mutate currentGen.
        rotateIfFull();
        // computeIfAbsent guarantees the mapping function runs at most once per key, but callers
        // that lose the race still return through this same call without ever invoking it. Track
        // whether *this* call was the one that parsed, so racing callers are still counted (as a
        // hit, since they got the value without parsing) instead of silently missing both counters.
        boolean[] parsed = {false};
        try {
            ParsedXfcc result = currentGen.computeIfAbsent(key, k -> {
                parsed[0] = true;
                recordMiss();
                try {
                    return supplier.parse();
                } catch (CertificateException | IOException e) {
                    throw new WrappedCheckedException(e);
                }
            });
            if (!parsed[0]) {
                recordHit();
            }
            return result;
        } catch (WrappedCheckedException e) {
            Throwable cause = e.getCause();
            if (cause instanceof CertificateException) {
                throw (CertificateException) cause;
            }
            if (cause instanceof IOException) {
                throw (IOException) cause;
            }
            throw new RuntimeException(cause);
        }
    }

    private void rotateIfFull() {
        if (currentGen.size() >= maxGenSize) {
            prevGen = currentGen;
            currentGen = new ConcurrentHashMap<>();
            this.rotations.increment();
            logRotation();
        }
    }

    private void recordHit() {
        this.hits.increment();
        if (LOGGER.isLoggable(Level.FINE)) {
            LOGGER.fine("Certificate cache hit; skipping certificate parsing");
        }
    }

    private void recordMiss() {
        this.misses.increment();
        if (LOGGER.isLoggable(Level.FINE)) {
            LOGGER.fine("Certificate cache miss; the certificate will be parsed");
        }
    }

    /** Supplies a {@link ParsedXfcc} bundle on a cache miss. */
    @FunctionalInterface
    public interface ParsedXfccSupplier {

        ParsedXfcc parse() throws CertificateException, IOException;
    }

    /** Carries a checked exception out of {@link ConcurrentHashMap#computeIfAbsent}. */
    private static final class WrappedCheckedException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        WrappedCheckedException(Throwable cause) {
            super(cause);
        }
    }

    /** Returns the number of lookups that were served from the cache. */
    public long getHitCount() {
        return this.hits.sum();
    }

    /** Returns the number of lookups that required the certificate to be parsed. */
    public long getMissCount() {
        return this.misses.sum();
    }

    /** Returns the number of generation rotations performed so far. */
    public long getRotationCount() {
        return this.rotations.sum();
    }

    /** Returns a snapshot of the cache counters, suitable for logging. */
    public String statistics() {
        long hitCount = this.hits.sum();
        long missCount = this.misses.sum();
        long lookups = hitCount + missCount;
        long hitRate = lookups == 0 ? 0 : (hitCount * 100) / lookups;
        return "rotations=" + this.rotations.sum() + ", hits=" + hitCount + ", misses=" + missCount
            + ", hit rate=" + hitRate + "%, capacity=" + (2 * this.maxGenSize) + " parsed XFCC entries";
    }

    private void logRotation() {
        // The first rotation is the moment the cache fills up and starts evicting, so report it once at INFO
        // where operators will see it without turning on FINE. Later rotations are routine and stay at FINE:
        // traffic with mostly unique certificates rotates every maxGenSize misses and would flood the log.
        boolean first = this.capacityReached.compareAndSet(false, true);
        Level level = first ? Level.INFO : Level.FINE;
        if (!LOGGER.isLoggable(level)) {
            return;
        }
        String message = "Certificate cache rotated a generation (" + statistics()
            + "). A low hit rate means the working set of certificates exceeds the cache size; raise"
            + " org.cloudfoundry.router.certificate.cache.size to retain more of them.";
        LOGGER.log(level, message);
    }
}
