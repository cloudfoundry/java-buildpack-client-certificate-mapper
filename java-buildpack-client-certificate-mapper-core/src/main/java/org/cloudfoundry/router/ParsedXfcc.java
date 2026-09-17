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

import java.security.cert.X509Certificate;

/**
 * Immutable bundle of everything derived from a single {@code X-Forwarded-Client-Cert} header value.
 *
 * <p>The {@link CertificateCache} keys this bundle by a SHA-256 digest of the raw header value so a
 * repeated header hits one cache entry and skips all of: {@link XfccEntry} one-pass parsing, X.509
 * decoding, and CF subject DN parsing. Under load with a small set of client certificates this is
 * the dominant hot path in the filter, so caching the parsed bundle rather than just the certificate
 * removes work that used to run on every request even after the X.509 cache was warm.
 *
 * <p>All fields except {@link #xfcc} may be {@code null}:
 * <ul>
 *   <li>{@link #certificate} is {@code null} when the entry is XFCC-shaped but has no {@code Cert=}
 *       field (e.g. only {@code Chain=} was sent).</li>
 *   <li>{@link #cfSubjectDn} is {@code null} when no {@code Subject=} was present or the subject
 *       could not be parsed as a CF DN.</li>
 * </ul>
 */
public final class ParsedXfcc {

    private final XfccEntry xfcc;

    private final X509Certificate certificate;

    private final CfSubjectDn cfSubjectDn;

    public ParsedXfcc(XfccEntry xfcc, X509Certificate certificate, CfSubjectDn cfSubjectDn) {
        this.xfcc = xfcc;
        this.certificate = certificate;
        this.cfSubjectDn = cfSubjectDn;
    }

    /** Parsed XFCC entry (never {@code null}; may be a non-XFCC placeholder). */
    public XfccEntry xfcc() {
        return xfcc;
    }

    /** Parsed X.509 certificate, or {@code null} when no {@code Cert=} field was present. */
    public X509Certificate certificate() {
        return certificate;
    }

    /** Parsed CF subject DN, or {@code null} when no CF-style {@code Subject=} was present. */
    public CfSubjectDn cfSubjectDn() {
        return cfSubjectDn;
    }
}
