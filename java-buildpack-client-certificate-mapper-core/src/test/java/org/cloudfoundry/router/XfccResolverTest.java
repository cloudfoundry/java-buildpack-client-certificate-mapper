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

import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

public final class XfccResolverTest {

    private static final String HASH = "078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b";

    private static final String NGINX_ESCAPED_CERT = "" +
        "%2D%2D%2D%2D%2DBEGIN%20CERTIFICATE%2D%2D%2D%2D%2D%0D%0AMIIDLTCCA" +
        "hWgAwIBAgIkMDg3ZjVmZGMtOThkNy00MGMwLTY0ZDMtZmQ5NWFmODMx%0D%0AOTh" +
        "kMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNVBAMMD2NyZWRodWJDbGllbnRDQTAe%0D" +
        "%0AFw0xNzA1MDIwMDQ5MzFaFw0xNzA1MDMwMDQ5MzFaMGIxMTAvBgNVBAsTKGFwc" +
        "Doy%0D%0AMzI4MmZkMS0zNWI0LTQ1ZGQtYTYwMi04Zjc2ZjRhNjBkMTExLTArBgN" +
        "VBAMTJDA4%0D%0AN2Y1ZmRjLTk4ZDctNDBjMC02NGQzLWZkOTVhZjgzMTk4ZDCCA" +
        "SIwDQYJKoZIhvcN%0D%0AAQEBBQADggEPADCCAQoCggEBAPhcSn56pIVWI0Rpwrk" +
        "C3WcvumLw%2B3i%2Foj3YBbEx%0D%0AAUAFJMFl%2Fyt1zpAghLvYOOiiUS%2FW0" +
        "4SKp8Z9FHlmNabJOzV40RIciSbYCW0tBeFG%0D%0AKNkgolTGamvRLZkkHUJdywE" +
        "QkvnMG7%2B2XczDBoCZ7fdBepg6gieSqGhQwl%2FsO7x%2F%0D%0ATouvQnujKwJ" +
        "LiXOKQq00TkT%2BMVEzOZyOMlqFh9r2XjUGuh1HnRM0IAj6buR5663t%0D%0A4lA" +
        "QqOluTAVNCKWSrAMIKb0G4QPTQ4pKRTeMEnTijFErtKlpzc64HYrBpufj1K%2Fq%" +
        "0D%0ATxYIy3EgeT3UVSclSub14M4%2Fr%2FmOmWotYP81BR1Ko7pxV28CAwEAAaM" +
        "TMBEwDwYD%0D%0AVR0RBAgwBocECv4AAjANBgkqhkiG9w0BAQsFAAOCAQEAuG8A3" +
        "3%2BUn2rvXA%2BqAf40%0D%0AgBponN2mjx0drasw%2FMqBnclUL1MYvOepqcGxx" +
        "NB%2F1Ok%2FbKKDMr03ugVaxzAdoknA%0D%0ANwIyY%2FghL6xHs%2FJrmuSGDs9" +
        "BeNF0y8TOpQmmjh1EDFtR9YFuTRP1OZ6XBf5fbd80%0D%0AQ684k%2FWu8ELywZJ" +
        "d53FKcTPJRQ%2FYjn4QFJORtcNFlvMFWTmJLLiMDbI8JBcqMLZH%0D%0AsgdyBtV" +
        "7kJdZU3nszgFEPspYzFfxQZmq6V%2BpJb%2BdmG2jYWrX%2FR21J9x1dJHBCoPp%" +
        "0D%0AXcqQm8pYsDxi%2BHTGS6an78sHqrvU5uQJq2MW8o6iBJR80bFgWSl7GTqK3" +
        "Xz5iTxU%0D%0AEw%3D%3D%0D%0A%2D%2D%2D%2D%2DEND%20CERTIFICATE%2D%2" +
        "D%2D%2D%2D%0D%0A";

    @Test
    public void identityOnlyXfccIsAlsoCached() throws Exception {
        CertificateCache cache = new CertificateCache(16);
        XfccResolver resolver = new XfccResolver(cache);
        String rawValue = "Hash=" + HASH + ";Subject=\"/CN=client\"";

        ParsedXfcc first = resolver.resolve(rawValue);
        assertThat(first.certificate()).isNull();
        assertThat(first.cfSubjectDn()).isNotNull();
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isZero();

        ParsedXfcc second = resolver.resolve(rawValue);
        assertThat(second).isSameAs(first);
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isEqualTo(1);
    }

    @Test
    public void xfccWithCertIsCachedAcrossCalls() throws Exception {
        CertificateCache cache = new CertificateCache(16);
        XfccResolver resolver = new XfccResolver(cache);
        String rawValue = "Hash=" + HASH + ";Cert=" + NGINX_ESCAPED_CERT;

        ParsedXfcc first = resolver.resolve(rawValue);
        assertThat(first.certificate()).isNotNull();
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isZero();

        ParsedXfcc second = resolver.resolve(rawValue);
        assertThat(second.certificate()).isSameAs(first.certificate());
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isEqualTo(1);
    }

    @Test
    public void rawNonXfccCertificateIsDecodedAndCached() throws Exception {
        CertificateCache cache = new CertificateCache(16);
        XfccResolver resolver = new XfccResolver(cache);

        ParsedXfcc parsed = resolver.resolve(NGINX_ESCAPED_CERT);

        assertThat(parsed.certificate()).isNotNull();
        assertThat(parsed.cfSubjectDn()).isNull();
        assertThat(cache.getMissCount()).isEqualTo(1);
    }

    /**
     * Covers the other of the two supported raw-certificate formats: plain base64-encoded DER
     * (no PEM armor, no URL-encoding), as produced e.g. by CF Gorouter's {@code xfcc_format: raw}.
     * {@code decodeHeader} tries {@link java.util.Base64} first and only falls back to
     * {@link java.net.URLDecoder} when that fails, so this exercises the base64 branch exclusively
     * and confirms it never touches the URL-decode/UTF-8 path.
     */
    @Test
    public void rawBase64DerCertificateIsDecodedAndMatchesPemEquivalent() throws Exception {
        XfccResolver resolver = new XfccResolver(new CertificateCache(16));
        X509Certificate expected = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
        String rawBase64Der = Base64.getEncoder().encodeToString(expected.getEncoded());

        ParsedXfcc parsed = resolver.resolve(rawBase64Der);

        assertThat(parsed.certificate()).isNotNull();
        assertThat(parsed.certificate().getEncoded()).isEqualTo(expected.getEncoded());
        assertThat(parsed.certificate().getSerialNumber()).isEqualTo(expected.getSerialNumber());
    }

    /**
     * Confirms the URL-encoded-PEM branch of {@code decodeHeader} round-trips the DER bytes
     * byte-for-byte: PEM is armored ASCII text (base64 body + header/footer lines), so decoding
     * the URL-encoding and re-encoding as UTF-8 cannot lose or alter any byte, unlike a raw binary
     * DER payload would. This is asserted here by comparing against a certificate decoded straight
     * from base64 DER with no PEM/URL-encoding step at all.
     */
    @Test
    public void urlEncodedPemCertificateMatchesRawDerByteForByte() throws Exception {
        XfccResolver resolver = new XfccResolver(new CertificateCache(16));

        X509Certificate viaPem = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
        String rawBase64Der = Base64.getEncoder().encodeToString(viaPem.getEncoded());
        X509Certificate viaRawDer = resolver.resolve(rawBase64Der).certificate();

        assertThat(viaPem.getEncoded()).isEqualTo(viaRawDer.getEncoded());
    }

    @Test
    public void xfccCertFieldAcceptsRawBase64DerAsWellAsUrlEncodedPem() throws Exception {
        XfccResolver resolver = new XfccResolver(new CertificateCache(16));
        X509Certificate expected = resolver.resolve(NGINX_ESCAPED_CERT).certificate();
        String rawBase64Der = Base64.getEncoder().encodeToString(expected.getEncoded());

        ParsedXfcc parsed = resolver.resolve("Hash=" + HASH + ";Cert=" + rawBase64Der);

        assertThat(parsed.certificate()).isNotNull();
        assertThat(parsed.certificate().getEncoded()).isEqualTo(expected.getEncoded());
    }

    @Test
    public void chainOnlyXfccYieldsNoCertificateButIsStillCached() throws Exception {
        CertificateCache cache = new CertificateCache(16);
        XfccResolver resolver = new XfccResolver(cache);
        String rawValue = "Hash=" + HASH + ";Chain=" + NGINX_ESCAPED_CERT;

        ParsedXfcc first = resolver.resolve(rawValue);
        assertThat(first.certificate()).isNull();
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isZero();

        ParsedXfcc second = resolver.resolve(rawValue);
        assertThat(second).isSameAs(first);
        assertThat(cache.getMissCount()).isEqualTo(1);
        assertThat(cache.getHitCount()).isEqualTo(1);
    }

    @Test
    public void resolveWorksWithCachingDisabled() throws Exception {
        XfccResolver resolver = new XfccResolver(null);

        ParsedXfcc parsed = resolver.resolve("Hash=" + HASH + ";Cert=" + NGINX_ESCAPED_CERT);

        assertThat(resolver.cache()).isNull();
        assertThat(parsed.certificate()).isNotNull();
    }
}
