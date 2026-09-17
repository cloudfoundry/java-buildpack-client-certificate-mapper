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

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public final class CertificateCacheTest {

    @SuppressWarnings("deprecation")
    private static X509Certificate fakeCert() {
        return new X509Certificate() {
            @Override public void checkValidity() {}
            @Override public void checkValidity(Date date) {}
            @Override public int getVersion() { return 3; }
            @Override public BigInteger getSerialNumber() { return BigInteger.ONE; }
            @Override public Principal getIssuerDN() { return () -> "issuer"; }
            @Override public Principal getSubjectDN() { return () -> "subject"; }
            @Override public Date getNotBefore() { return new Date(0); }
            @Override public Date getNotAfter() { return new Date(Long.MAX_VALUE); }
            @Override public byte[] getTBSCertificate() { return new byte[0]; }
            @Override public byte[] getSignature() { return new byte[0]; }
            @Override public String getSigAlgName() { return ""; }
            @Override public String getSigAlgOID() { return ""; }
            @Override public byte[] getSigAlgParams() { return new byte[0]; }
            @Override public boolean[] getIssuerUniqueID() { return new boolean[0]; }
            @Override public boolean[] getSubjectUniqueID() { return new boolean[0]; }
            @Override public boolean[] getKeyUsage() { return new boolean[0]; }
            @Override public int getBasicConstraints() { return -1; }
            @Override public byte[] getEncoded() { return new byte[0]; }
            @Override public void verify(PublicKey key) {}
            @Override public void verify(PublicKey key, String provider) {}
            @Override public String toString() { return "fakeCert"; }
            @Override public PublicKey getPublicKey() { return null; }
            @Override public boolean hasUnsupportedCriticalExtension() { return false; }
            @Override public Set<String> getCriticalExtensionOIDs() { return null; }
            @Override public Set<String> getNonCriticalExtensionOIDs() { return null; }
            @Override public byte[] getExtensionValue(String oid) { return new byte[0]; }
        };
    }

    /** Wraps a {@link X509Certificate} into a minimal {@link ParsedXfcc} cache entry (non-XFCC placeholder). */
    private static ParsedXfcc fakeEntry() {
        return new ParsedXfcc(new XfccEntry(""), fakeCert(), null);
    }

    @Test
    public void getMissReturnsNull() {
        CertificateCache cache = new CertificateCache(10);
        assertThat(cache.get("missing")).isNull();
    }

    @Test
    public void putAndGetReturnsSameInstance() {
        CertificateCache cache = new CertificateCache(10);
        ParsedXfcc entry = fakeEntry();
        cache.put("key1", entry);
        assertThat(cache.get("key1")).isSameAs(entry);
    }

    @Test
    public void entryInPreviousGenerationIsStillReturned() {
        CertificateCache cache = new CertificateCache(2);
        ParsedXfcc entry = fakeEntry();
        cache.put("key1", entry);
        // fill current gen to trigger rotation
        cache.put("key2", fakeEntry());
        cache.put("key3", fakeEntry()); // triggers rotation: key1 moves to prevGen
        assertThat(cache.get("key1")).isSameAs(entry);
    }

    @Test
    public void entryEvictedAfterTwoRotations() {
        CertificateCache cache = new CertificateCache(2);
        ParsedXfcc entry = fakeEntry();
        cache.put("key1", entry);
        // first rotation: key1 goes to prevGen
        cache.put("key2", fakeEntry());
        cache.put("key3", fakeEntry());
        // second rotation: prevGen (with key1) is discarded
        cache.put("key4", fakeEntry());
        cache.put("key5", fakeEntry());
        assertThat(cache.get("key1")).isNull();
    }

    @Test
    public void countersTrackHitsAndMisses() {
        CertificateCache cache = new CertificateCache(10);
        cache.put("key1", fakeEntry());
        cache.get("key1");
        cache.get("key1");
        cache.get("absent");

        assertThat(cache.getHitCount()).isEqualTo(2);
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getRotationCount()).isZero();
    }

    @Test
    public void rotationCountIsIncrementedOnEachRotation() {
        CertificateCache cache = new CertificateCache(2);
        cache.put("key1", fakeEntry());
        cache.put("key2", fakeEntry());
        cache.put("key3", fakeEntry()); // first rotation
        cache.put("key4", fakeEntry());
        cache.put("key5", fakeEntry()); // second rotation

        assertThat(cache.getRotationCount()).isEqualTo(2);
    }

    @Test
    public void statisticsReportsHitRateAndCapacity() {
        CertificateCache cache = new CertificateCache(2);
        cache.put("key1", fakeEntry());
        cache.get("key1");
        cache.get("absent");

        assertThat(cache.statistics()).isEqualTo("rotations=0, hits=1, misses=1, hit rate=50%, capacity=4 parsed XFCC entries");
    }

    @Test
    public void statisticsReportsZeroHitRateWithoutLookups() {
        assertThat(new CertificateCache(8).statistics()).isEqualTo("rotations=0, hits=0, misses=0, hit rate=0%, capacity=16 parsed XFCC entries");
    }

    @Test
    public void currentGenEntryTakesPrecedenceOverPreviousGen() {
        CertificateCache cache = new CertificateCache(2);
        ParsedXfcc oldEntry = fakeEntry();
        ParsedXfcc newEntry = fakeEntry();
        cache.put("key1", oldEntry);
        // trigger rotation
        cache.put("key2", fakeEntry());
        cache.put("key3", fakeEntry());
        // re-add key1 with a new entry in the fresh current gen
        cache.put("key1", newEntry);
        assertThat(cache.get("key1")).isSameAs(newEntry);
    }

    @Test
    public void peekReturnsEntryAndRecordsHitWithoutInvokingSupplier() {
        CertificateCache cache = new CertificateCache(4);
        ParsedXfcc entry = fakeEntry();
        cache.put("key1", entry);

        assertThat(cache.peek("key1")).isSameAs(entry);
        assertThat(cache.getHitCount()).isEqualTo(1);
        assertThat(cache.getMissCount()).isZero();
    }

    @Test
    public void peekReturnsNullAndRecordsNothingOnMiss() {
        CertificateCache cache = new CertificateCache(4);

        assertThat(cache.peek("missing")).isNull();
        assertThat(cache.getHitCount()).isZero();
        assertThat(cache.getMissCount()).isZero();
    }

    @Test
    public void getOrComputeReturnsCachedValueOnHit() throws Exception {
        CertificateCache cache = new CertificateCache(4);
        ParsedXfcc entry = fakeEntry();
        cache.put("key1", entry);
        java.util.concurrent.atomic.AtomicInteger supplierInvocations = new java.util.concurrent.atomic.AtomicInteger();

        ParsedXfcc result = cache.getOrCompute("key1", () -> {
            supplierInvocations.incrementAndGet();
            return fakeEntry();
        });

        assertThat(result).isSameAs(entry);
        assertThat(supplierInvocations).hasValue(0);
    }

    @Test
    public void getOrComputeInvokesSupplierExactlyOncePerKeyUnderConcurrentMiss() throws Exception {
        // Reproduces the thundering-herd case: many threads with the same cache-cold key must
        // trigger the supplier only once. This is the scenario that caused a parse-spike under
        // 100 tps of identical XFCC headers before getOrCompute was introduced.
        CertificateCache cache = new CertificateCache(128);
        java.util.concurrent.atomic.AtomicInteger supplierInvocations = new java.util.concurrent.atomic.AtomicInteger();
        ParsedXfcc sharedEntry = fakeEntry();
        int threadCount = 100;
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(threadCount);
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(threadCount);
        java.util.List<ParsedXfcc> results = java.util.Collections.synchronizedList(new java.util.ArrayList<>());

        try {
            for (int i = 0; i < threadCount; i++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        results.add(cache.getOrCompute("shared-key", () -> {
                            supplierInvocations.incrementAndGet();
                            // Small pause so concurrent threads all reach computeIfAbsent while the
                            // first supplier is still running — this is what a real cert parse does.
                            try {
                                Thread.sleep(20);
                            } catch (InterruptedException ignored) {
                                Thread.currentThread().interrupt();
                            }
                            return sharedEntry;
                        }));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertThat(done.await(10, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        } finally {
            pool.shutdownNow();
        }

        assertThat(supplierInvocations).hasValue(1);
        assertThat(results).hasSize(threadCount);
        for (ParsedXfcc result : results) {
            assertThat(result).isSameAs(sharedEntry);
        }
        // The single winning thread records a miss; every other thread that raced on the same
        // key and received the already-computed value without parsing must record a hit, not
        // be dropped from the counters entirely.
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isEqualTo(threadCount - 1);
    }

    @Test
    public void getOrComputeDoesNotCacheOnSupplierException() {
        CertificateCache cache = new CertificateCache(4);

        assertThatThrownBy(() -> cache.getOrCompute("key1", () -> {
            throw new CertificateException("bad cert");
        })).isInstanceOf(CertificateException.class).hasMessage("bad cert");

        // Next call retries — no poisoned entry left behind.
        java.util.concurrent.atomic.AtomicInteger invocations = new java.util.concurrent.atomic.AtomicInteger();
        ParsedXfcc entry = fakeEntry();
        try {
            ParsedXfcc result = cache.getOrCompute("key1", () -> {
                invocations.incrementAndGet();
                return entry;
            });
            assertThat(result).isSameAs(entry);
            assertThat(invocations).hasValue(1);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

}
