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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Servlet-independent core of the client-certificate mapper: turns a single raw
 * {@code X-Forwarded-Client-Cert} header entry into a {@link ParsedXfcc} bundle, decoding any
 * certificate and parsing the XFCC fields, optionally using a {@link CertificateCache}.
 *
 * <p>This logic is shared by the {@code javax} and {@code jakarta} filters so the two differ only in
 * their Servlet-API-specific glue (reading headers, setting request attributes, header stripping).
 */
public final class XfccResolver {

    private static final Logger LOGGER = Logger.getLogger(XfccResolver.class.getName());

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private final CertificateFactory certificateFactory;

    /** {@code null} when caching is disabled. */
    private final CertificateCache certificateCache;

    /** {@code null} when SHA-256 is unavailable (extremely unusual) or caching is disabled; in
     *  that case every request falls back to inline parsing without a digest-based cache key.
     *  When present, this instance is never digested directly -- only {@link MessageDigest#clone()}d
     *  per call (see {@link #sha256Hex}), since {@code MessageDigest} instances are not thread-safe.
     *  Cloning a prototype avoids the provider-lookup cost of {@link MessageDigest#getInstance}
     *  on every request. */
    private final MessageDigest digestPrototype;

    /** Whether {@link #digestPrototype} supports {@link MessageDigest#clone()}, probed once at
     *  construction (see {@link #probeCloneSupport}) so {@link #sha256Hex} never has to retry
     *  {@code clone()} and re-catch {@link CloneNotSupportedException} on every request; it is
     *  meaningless when {@link #digestPrototype} is {@code null}. */
    private final boolean cloneSupported;

    /** @param certificateCache the cache to use, or {@code null} to disable caching */
    public XfccResolver(CertificateCache certificateCache) throws CertificateException {
        this.certificateFactory = CertificateFactory.getInstance("X.509");
        this.certificateCache = certificateCache;
        this.digestPrototype = certificateCache != null ? createSha256Prototype() : null;
        this.cloneSupported = this.digestPrototype != null && probeCloneSupport(this.digestPrototype);
    }

    /** Creates the SHA-256 prototype {@link MessageDigest} once at construction, logging a warning
     *  if unavailable so operators learn about the degraded (uncached) mode at startup rather than
     *  from a flood of per-request log lines once traffic arrives. Returns {@code null} on failure. */
    private static MessageDigest createSha256Prototype() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warning("SHA-256 algorithm not available; the certificate cache is disabled for the "
                + "lifetime of this filter");
            return null;
        }
    }

    /** Probes once, at construction, whether {@code prototype} supports {@link MessageDigest#clone()}
     *  (true for the JDK's built-in SHA-256 implementation, but not guaranteed by the JCA contract
     *  for every provider). Logging and remembering the result here means {@link #sha256Hex} never
     *  needs to retry {@code clone()} and re-catch {@link CloneNotSupportedException} on every one of
     *  potentially millions of requests -- it takes the {@code getInstance} path directly instead. */
    private static boolean probeCloneSupport(MessageDigest prototype) {
        try {
            prototype.clone();
            return true;
        } catch (CloneNotSupportedException e) {
            LOGGER.warning("MessageDigest.clone() not supported by the SHA-256 provider; falling back "
                + "to MessageDigest.getInstance() per request");
            return false;
        }
    }

    /** The certificate cache in use, or {@code null} when caching is disabled. */
    public CertificateCache cache() {
        return this.certificateCache;
    }

    /** Returns the parsed bundle for {@code rawValue}, using the cache when enabled. The cache is
     *  keyed by a SHA-256 digest of the raw header value and consulted, via {@link CertificateCache#peek}
     *  <em>before</em> {@code rawValue} is parsed into an {@link XfccEntry} -- a hit returns the
     *  previously cached bundle directly, so a repeat of the same header does not re-run the one-pass
     *  field scan just to discard it. Every entry that produces a digest is cached on a miss, including
     *  identity-only XFCC headers (e.g. CF app-identity headers carrying only {@code Hash=}/
     *  {@code Subject=}) and unsupported {@code Chain=}-only entries: those have no expensive ASN.1
     *  parse to amortise, but since the digest is computed for them anyway (whether an entry carries a
     *  certificate can only be known after parsing it), storing the result too means a repeat of the
     *  same identity-only header also skips the field-map parse, at negligible extra memory cost. When
     *  the SHA-256 algorithm is unavailable (extremely unusual -- checked and logged once at
     *  construction, see {@link #digestPrototype}) every request falls back to inline parsing rather
     *  than caching under an unsafe long key. */
    public ParsedXfcc resolve(String rawValue) throws CertificateException, IOException {
        if (this.certificateCache != null) {
            String cacheKey = sha256Hex(rawValue);
            if (cacheKey != null) {
                ParsedXfcc cached = this.certificateCache.peek(cacheKey);
                if (cached != null) {
                    return cached;
                }
                return this.certificateCache.getOrCompute(cacheKey, () -> parseEntry(new XfccEntry(rawValue), rawValue));
            }
        }
        return parseEntry(new XfccEntry(rawValue), rawValue);
    }

    /** Parses a pre-detected {@link XfccEntry} into a {@link ParsedXfcc} bundle: the entry, the
     *  decoded {@link X509Certificate} (if a {@code Cert=} field is present or the value is a raw
     *  certificate), and the {@link CfSubjectDn} derived from any {@code Subject=} field.
     *  On the cache miss path this is invoked exactly once per key by
     *  {@link CertificateCache#getOrCompute}. */
    private ParsedXfcc parseEntry(XfccEntry xfcc, String rawValue) throws CertificateException, IOException {
        if (xfcc.resemblesXfcc()) {
            if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("XFCC entry received with fields: " + xfcc.fieldNames());
            }
            if (xfcc.hasField(XfccField.HASH) && !XfccHeaderParser.isValidSha256Hex(xfcc.get(XfccField.HASH))) {
                LOGGER.warning("X-Forwarded-Client-Cert Hash= value does not look like a SHA-256 hex digest");
            }
            X509Certificate cert = null;
            if (xfcc.hasField(XfccField.CERT)) {
                cert = generateCertificate(xfcc.get(XfccField.CERT));
            } else if (xfcc.hasField(XfccField.CHAIN)) {
                LOGGER.warning("X-Forwarded-Client-Cert contains Chain= but no Cert= field; Chain= is not supported and the certificate will not be mapped.");
            }
            CfSubjectDn dn = xfcc.hasField(XfccField.SUBJECT)
                    ? XfccHeaderParser.parseCfSubjectDn(xfcc.get(XfccField.SUBJECT))
                    : null;
            return new ParsedXfcc(xfcc, cert, dn);
        }
        // Non-XFCC raw cert: no XFCC fields to extract, no CF DN.
        return new ParsedXfcc(xfcc, generateCertificate(rawValue), null);
    }

    private X509Certificate generateCertificate(String certData) throws CertificateException, IOException {
        try (InputStream in = new ByteArrayInputStream(decodeHeader(certData))) {
            return (X509Certificate) this.certificateFactory.generateCertificate(in);
        }
    }

    /**
     * Decodes a header value in either of the two supported raw-certificate formats:
     * <ol>
     *   <li>Plain base64-encoded DER (e.g. CF Gorouter {@code xfcc_format: raw}) -- tried first.</li>
     *   <li>URL-encoded PEM (e.g. nginx {@code $ssl_client_escaped_cert}, Envoy XFCC {@code Cert=}/
     *       {@code Chain=}, both documented as "URL encoded PEM format") -- the fallback below.</li>
     * </ol>
     * The fallback is safe to round-trip through a {@code String} as UTF-8: PEM is armored ASCII
     * text (base64 body plus {@code -----BEGIN/END-----} lines), never raw binary DER, so
     * URL-decoding it and re-encoding as UTF-8 cannot lose or alter a byte. Base64 is tried first
     * specifically so a raw DER header (whose base64 alphabet never collides with PEM's
     * {@code -}/space/newline or their percent-escaped forms) is never routed through this
     * String-based fallback.
     */
    private byte[] decodeHeader(String rawCertificate) {
        try {
            return Base64.getDecoder().decode(rawCertificate);
        } catch (IllegalArgumentException e1) {
            try {
                return URLDecoder.decode(rawCertificate, "utf-8").getBytes(StandardCharsets.UTF_8);
            } catch (UnsupportedEncodingException e2) {
                throw new IllegalArgumentException("Header contains value that is neither base64 nor url encoded");
            }
        }
    }

    /** Returns the SHA-256 digest of {@code input} as 64 lowercase hex characters, or {@code null} if
     *  {@link #digestPrototype} is {@code null} (in which case the caller falls back to no caching
     *  for that request rather than using an unsafe long key). {@code MessageDigest} instances are not
     *  thread-safe, so each call clones a fresh instance off {@link #digestPrototype} rather than
     *  calling {@link MessageDigest#getInstance} again -- cloning duplicates internal digest state
     *  directly and skips the provider-lookup machinery {@code getInstance} performs on every call.
     *  Falls back to {@code getInstance} for every call if the provider's implementation is not
     *  {@link Cloneable} (uncommon; the JDK's built-in SHA-256 implementation is) -- that check is
     *  done once at construction (see {@link #cloneSupported}), not retried per request. Note:
     *  {@code input} is the header
     *  value exactly as received -- either URL-encoded PEM text or base64-encoded DER (see
     *  {@link #decodeHeader}) -- never the decoded DER bytes, so this digest intentionally differs
     *  from the Envoy XFCC {@code Hash=} field (which is SHA-256 of the decoded DER). This is fine
     *  for cache identity but the two values must not be compared. Cloning is preferred over
     *  {@code getInstance} here because it avoids the provider registry's shared lookup path
     *  entirely, rather than merely being faster on average; benchmark numbers for this are
     *  JVM- and provider-specific and are kept out of this Javadoc for that reason (see the pull
     *  request discussion for measurements). */
    private String sha256Hex(String input) {
        if (this.digestPrototype == null) {
            return null;
        }
        MessageDigest md;
        if (this.cloneSupported) {
            try {
                md = (MessageDigest) this.digestPrototype.clone();
            } catch (CloneNotSupportedException e) {
                // Unreachable in practice: probed once at construction (see #cloneSupported) and
                // cannot change at runtime. Fall back safely rather than throwing if it somehow does.
                return null;
            }
        } else {
            try {
                md = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                // Unreachable in practice: availability was already confirmed at construction and
                // cannot change at runtime. Fall back safely rather than throwing if it somehow does.
                return null;
            }
        }
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        char[] out = new char[digest.length * 2];
        for (int i = 0; i < digest.length; i++) {
            int b = digest[i] & 0xff;
            out[i * 2] = HEX[b >>> 4];
            out[i * 2 + 1] = HEX[b & 0x0f];
        }
        return new String(out);
    }
}
