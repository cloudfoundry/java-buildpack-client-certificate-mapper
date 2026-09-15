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

    /** @param certificateCache the cache to use, or {@code null} to disable caching */
    public XfccResolver(CertificateCache certificateCache) throws CertificateException {
        this.certificateFactory = CertificateFactory.getInstance("X.509");
        this.certificateCache = certificateCache;
    }

    /** The certificate cache in use, or {@code null} when caching is disabled. */
    public CertificateCache cache() {
        return this.certificateCache;
    }

    /** Returns the parsed bundle for {@code rawValue}, using the cache when enabled. The cache is
     *  consulted, by digest of the raw header value, <em>before</em> {@code rawValue} is parsed into
     *  an {@link XfccEntry} — a hit returns the previously cached bundle directly, so a repeat of the
     *  same header does not re-run the one-pass field scan just to discard it. Only entries that carry
     *  a certificate to decode are stored on a miss: an XFCC entry with a {@code Cert=} field, or a raw
     *  (non-XFCC) certificate value. XFCC entries without {@code Cert=} (e.g. CF app-identity headers
     *  carrying only {@code Hash=}/{@code Subject=}) have no expensive ASN.1 parse to amortise, so they
     *  are parsed inline and never stored — though the digest is still computed for them, since whether
     *  an entry carries a certificate can only be known after parsing it. When the SHA-256 algorithm is
     *  unavailable (extremely unusual — logged once by {@link #sha256Hex}) the request also falls back
     *  to inline parsing rather than caching under an unsafe long key. */
    public ParsedXfcc resolve(String rawValue) throws CertificateException, IOException {
        if (this.certificateCache != null) {
            String cacheKey = sha256Hex(rawValue);
            if (cacheKey != null) {
                ParsedXfcc cached = this.certificateCache.peek(cacheKey);
                if (cached != null) {
                    return cached;
                }
                XfccEntry xfcc = new XfccEntry(rawValue);
                boolean carriesCertificate = xfcc.resemblesXfcc() ? xfcc.hasField(XfccField.CERT) : true;
                if (carriesCertificate) {
                    return this.certificateCache.getOrCompute(cacheKey, () -> parseEntry(xfcc, rawValue));
                }
                return parseEntry(xfcc, rawValue);
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
     *  the SHA-256 algorithm is unavailable (in which case the caller falls back to no caching for that
     *  request rather than using an unsafe long key). MessageDigest instances are not thread-safe, so a
     *  fresh one is obtained per call; the cost is dominated by the digest computation itself.
     *  Note: {@code input} is the URL-encoded PEM or base64 DER header value — not the decoded DER —
     *  so this digest intentionally differs from the Envoy XFCC {@code Hash=} field. This is fine for
     *  cache identity but the two values must not be compared. */
    private String sha256Hex(String input) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warning("SHA-256 algorithm not available; skipping certificate cache for this request");
            return null;
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
