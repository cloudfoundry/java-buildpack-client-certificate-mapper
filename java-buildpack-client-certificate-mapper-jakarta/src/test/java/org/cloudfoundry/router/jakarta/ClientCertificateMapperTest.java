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

package org.cloudfoundry.router.jakarta;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.cloudfoundry.router.XfccAttributes;
import org.cloudfoundry.router.CertificateCache;

import static org.assertj.core.api.Assertions.assertThat;

public final class ClientCertificateMapperTest {

    private static final String CERTIFICATE_1 = "" +
        "MIIDLTCCAhWgAwIBAgIkMDg3ZjVmZGMtOThkNy00MGMwLTY0ZDMtZmQ5NWFmODMx" +
        "OThkMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNVBAMMD2NyZWRodWJDbGllbnRDQTAe" +
        "Fw0xNzA1MDIwMDQ5MzFaFw0xNzA1MDMwMDQ5MzFaMGIxMTAvBgNVBAsTKGFwcDoy" +
        "MzI4MmZkMS0zNWI0LTQ1ZGQtYTYwMi04Zjc2ZjRhNjBkMTExLTArBgNVBAMTJDA4" +
        "N2Y1ZmRjLTk4ZDctNDBjMC02NGQzLWZkOTVhZjgzMTk4ZDCCASIwDQYJKoZIhvcN" +
        "AQEBBQADggEPADCCAQoCggEBAPhcSn56pIVWI0RpwrkC3WcvumLw+3i/oj3YBbEx" +
        "AUAFJMFl/yt1zpAghLvYOOiiUS/W04SKp8Z9FHlmNabJOzV40RIciSbYCW0tBeFG" +
        "KNkgolTGamvRLZkkHUJdywEQkvnMG7+2XczDBoCZ7fdBepg6gieSqGhQwl/sO7x/" +
        "TouvQnujKwJLiXOKQq00TkT+MVEzOZyOMlqFh9r2XjUGuh1HnRM0IAj6buR5663t" +
        "4lAQqOluTAVNCKWSrAMIKb0G4QPTQ4pKRTeMEnTijFErtKlpzc64HYrBpufj1K/q" +
        "TxYIy3EgeT3UVSclSub14M4/r/mOmWotYP81BR1Ko7pxV28CAwEAAaMTMBEwDwYD" +
        "VR0RBAgwBocECv4AAjANBgkqhkiG9w0BAQsFAAOCAQEAuG8A33+Un2rvXA+qAf40" +
        "gBponN2mjx0drasw/MqBnclUL1MYvOepqcGxxNB/1Ok/bKKDMr03ugVaxzAdoknA" +
        "NwIyY/ghL6xHs/JrmuSGDs9BeNF0y8TOpQmmjh1EDFtR9YFuTRP1OZ6XBf5fbd80" +
        "Q684k/Wu8ELywZJd53FKcTPJRQ/Yjn4QFJORtcNFlvMFWTmJLLiMDbI8JBcqMLZH" +
        "sgdyBtV7kJdZU3nszgFEPspYzFfxQZmq6V+pJb+dmG2jYWrX/R21J9x1dJHBCoPp" +
        "XcqQm8pYsDxi+HTGS6an78sHqrvU5uQJq2MW8o6iBJR80bFgWSl7GTqK3Xz5iTxU" +
        "Ew==";

    private static final String CERTIFICATE_2 = "" +
        "MIIC1TCCAb2gAwIBAgIUL3dmX9jNj2XqQaXv9noNfU84VoowDQYJKoZIhvcNAQEL" +
        "BQAwGjEYMBYGA1UEAwwPY3JlZGh1YkNsaWVudENBMB4XDTE3MDMzMDE5MTg0NVoX" +
        "DTE4MDMzMDE5MTg0NVowGjEYMBYGA1UEAwwPY3JlZGh1YkNsaWVudENBMIIBIjAN" +
        "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz1bJ1NkS+uDl3xMo8fvPFRsXdZUW" +
        "Un4N9nOfX/bfTWHrDKgW6+qrkkDBW4NLw0IHfgV99HwAygmiMC5La2HJg3JzcRMn" +
        "dq9MosrNjv5wVtkQAReLVCcZ+EMb4f+0tlbespsfMQpKYfksovXHTSv+zbvbE+pX" +
        "ObSUYpbZ09LtvbVL9s6hO5E9P9uXuV+ZSOZTISqtEIF6sXOKjx6WTCanG6jqf4+4" +
        "Lyasffen18NcMld6f7cfEgExUO7OVN86J28+LcILICAOB2m8ug4KnDkigaJp25ou" +
        "bPl/YnJtMh75buBjiOLI5p9j/n2mliUTKC5fJ54fb6MoMKXgXPAC7bcz5wIDAQAB" +
        "oxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBXc7cDaA8D" +
        "Iuoxnt5SVAk9R664OiMxOiQJ7oavdcU1S2hS22MOzAM1gMAwur1C8fmjcHthma4a" +
        "IFzzyvWlT3cfKmr+e1CVU0fOr1f4kFFval4kSa9uFbqaqQlj6dovoO34W9eadTyN" +
        "mACol2RdG0tjYWzbUaHdA21PdcezhiVw+PnXbzfKSnjWoxv0id1JTTPnVqfghTjG" +
        "pEqerOIo3+YRhkUsUEhJ9SFa58dtlKRPtKQjSuMTeBgQiU7WCpueFfPqRM1Ab7bP" +
        "OeiChAJVyknz/Mu1KmQxoZ43JfCyUIdtT5oE7CWIJt3qVwJYLgykuYV8vXEnIALB" +
        "p/ob7SaWTJJO";

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


    private final MockFilterChain filterChain = new MockFilterChain();

    private final ClientCertificateMapper mapper;

    private final MockHttpServletRequest request = new MockHttpServletRequest();

    private final MockHttpServletResponse response = new MockHttpServletResponse();

    public ClientCertificateMapperTest() throws CertificateException {
        this.mapper = new ClientCertificateMapper();
    }

    @Test
    public void emptyHeader() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, "");

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
    }

    @Test
    public void invalidHeader() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, "Invalid Header Value");

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
    }

    @Test
    public void invalidMultipleHeaders() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, CERTIFICATE_1);
        this.request.addHeader(ClientCertificateMapper.HEADER, "Invalid Header Value");

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
    }

    @Test
    public void invalidMultipleInOneHeader() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, String.format("%s,Invalid Header Value", CERTIFICATE_1));

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
    }

    @Test
    public void multipleHeaders() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, CERTIFICATE_1);
        this.request.addHeader(ClientCertificateMapper.HEADER, CERTIFICATE_2);

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat((X509Certificate[]) this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).hasSize(2);
    }

    @Test
    public void multipleInOneHeader() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, String.format("%s,%s", CERTIFICATE_1, CERTIFICATE_2));

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat((X509Certificate[]) this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).hasSize(2);
    }

    @Test
    public void nginxHeader() throws IOException, ServletException {

        this.request.addHeader(ClientCertificateMapper.HEADER, String.format("%s", NGINX_ESCAPED_CERT));

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat((X509Certificate[]) this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).hasSize(1);
    }

    @Test
    public void noHeader() throws IOException, ServletException {
        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
    }

    @Test
    public void xfccHashOnly() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, "Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b");

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
    }

    @Test
    public void xfccWithCert() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, "By=spiffe%3A%2F%2Fcluster.local;Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b;Cert=" + NGINX_ESCAPED_CERT);

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat((X509Certificate[]) this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).hasSize(1);
    }

    @Test
    public void xfccCaseInsensitiveKeys() throws IOException, ServletException {
        // Keys are case-insensitive per the Envoy XFCC spec
        this.request.addHeader(ClientCertificateMapper.HEADER, "hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b");

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
    }

    @Test
    public void xfccCaseInsensitiveCert() throws IOException, ServletException {
        // Keys are case-insensitive per the Envoy XFCC spec
        this.request.addHeader(ClientCertificateMapper.HEADER, "hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b;cert=" + NGINX_ESCAPED_CERT);

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat((X509Certificate[]) this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).hasSize(1);
    }

    @Test
    public void xfccSubjectWithSemicolonDoesNotBreakCert() throws IOException, ServletException {
        // Subject values are always double-quoted; semicolons inside quotes must not split the field
        this.request.addHeader(ClientCertificateMapper.HEADER,
            "Subject=\"/C=US/ST=CA;L=SF\";Cert=" + NGINX_ESCAPED_CERT);

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat((X509Certificate[]) this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).hasSize(1);
    }

    @Test
    public void xfccCommaDelimitedWithWhitespace() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER,
            "By=spiffe%3A%2F%2Fcluster.local;Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b;Cert=" + NGINX_ESCAPED_CERT
            + " , By=spiffe%3A%2F%2Fcluster.local;Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b;Cert=" + NGINX_ESCAPED_CERT);

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat((X509Certificate[]) this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).hasSize(2);
    }

    @Test
    public void xfccHashAttributeSetWhenHashOnly() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, "Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b");

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.request.getAttribute(XfccAttributes.HASH))
            .isEqualTo("078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b");
        assertThat(this.request.getAttribute(XfccAttributes.SUBJECT)).isNull();
    }

    @Test
    public void xfccHashAndSubjectAttributesSet() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER,
            "Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b;Subject=\"/CN=client\"");

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.request.getAttribute(XfccAttributes.HASH))
            .isEqualTo("078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b");
        assertThat(this.request.getAttribute(XfccAttributes.SUBJECT))
            .isEqualTo("/CN=client");
    }

    @Test
    public void rawCertHasNoXfccAttributes() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, CERTIFICATE_1);

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.request.getAttribute(XfccAttributes.HASH)).isNull();
        assertThat(this.request.getAttribute(XfccAttributes.SUBJECT)).isNull();
    }

    @Test
    public void xfccHashAndSubjectWithCfStyleOusNoException() throws IOException, ServletException {
        // CF router XFCC: hash-only (no Cert=), subject with UUID-based OUs and commas inside quotes
        this.request.addHeader(ClientCertificateMapper.HEADER,
            "Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b;" +
            "Subject=\"CN=12345678-1234-1234-1234-123456789012," +
            "OU=app:aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb," +
            "OU=space:cccccccc-4444-5555-6666-dddddddddddd," +
            "OU=organization:eeeeeeee-7777-8888-9999-ffffffffffff\"");

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
        assertThat(this.request.getAttribute(XfccAttributes.HASH))
            .isEqualTo("078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b");
        assertThat(this.request.getAttribute(XfccAttributes.SUBJECT))
            .isEqualTo("CN=12345678-1234-1234-1234-123456789012," +
                "OU=app:aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb," +
                "OU=space:cccccccc-4444-5555-6666-dddddddddddd," +
                "OU=organization:eeeeeeee-7777-8888-9999-ffffffffffff");
        assertThat(this.request.getAttribute(XfccAttributes.APP_GUID))
            .isEqualTo("aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb");
        assertThat(this.request.getAttribute(XfccAttributes.SPACE_GUID))
            .isEqualTo("cccccccc-4444-5555-6666-dddddddddddd");
        assertThat(this.request.getAttribute(XfccAttributes.ORG_GUID))
            .isEqualTo("eeeeeeee-7777-8888-9999-ffffffffffff");
        assertThat(this.request.getAttribute(XfccAttributes.INSTANCE_GUID))
            .isEqualTo("12345678-1234-1234-1234-123456789012");
    }

    @Test
    public void malformedUrlEncodedCertDoesNotThrow() throws IOException, ServletException {
        // %GG is invalid URL encoding; URLDecoder throws IllegalArgumentException
        // doFilter() must catch it, log, and let the request proceed
        this.request.addHeader(ClientCertificateMapper.HEADER, "%GGinvalidcert");

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
    }

    @Test
    public void xfccWithMalformedCertDoesNotThrow() throws IOException, ServletException {
        // XFCC Cert= field with invalid URL encoding; URLDecoder throws IllegalArgumentException
        // doFilter() must catch it, log, and let the request proceed
        this.request.addHeader(ClientCertificateMapper.HEADER,
            "Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b;Cert=%GGinvalid");

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
    }

    @Test
    public void xfccMultipleEntriesFirstHashWins() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER,
            "Hash=aaaa000000000000000000000000000000000000000000000000000000000000;Subject=\"/CN=first\"," +
            "Hash=bbbb000000000000000000000000000000000000000000000000000000000000;Subject=\"/CN=second\"");

        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.request.getAttribute(XfccAttributes.HASH))
            .isEqualTo("aaaa000000000000000000000000000000000000000000000000000000000000");
        assertThat(this.request.getAttribute(XfccAttributes.SUBJECT))
            .isEqualTo("/CN=first");
    }

    @Test
    public void xfccCacheHit() throws IOException, ServletException {
        String header = "Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b;Cert=" + NGINX_ESCAPED_CERT;
        this.request.addHeader(ClientCertificateMapper.HEADER, header);
        this.mapper.doFilter(this.request, this.response, this.filterChain);
        X509Certificate first = ((X509Certificate[]) this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE))[0];

        MockHttpServletRequest request2 = new MockHttpServletRequest();
        request2.addHeader(ClientCertificateMapper.HEADER, header);
        this.mapper.doFilter(request2, this.response, new MockFilterChain());
        X509Certificate second = ((X509Certificate[]) request2.getAttribute(ClientCertificateMapper.ATTRIBUTE))[0];

        assertThat(second).isSameAs(first);
    }

    @Test
    public void rawCacheHitSha256() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, CERTIFICATE_1);
        this.mapper.doFilter(this.request, this.response, this.filterChain);
        X509Certificate first = ((X509Certificate[]) this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE))[0];

        MockHttpServletRequest request2 = new MockHttpServletRequest();
        request2.addHeader(ClientCertificateMapper.HEADER, CERTIFICATE_1);
        this.mapper.doFilter(request2, this.response, new MockFilterChain());
        X509Certificate second = ((X509Certificate[]) request2.getAttribute(ClientCertificateMapper.ATTRIBUTE))[0];

        assertThat(second).isSameAs(first);
    }

    @Test
    public void stripXfccHeaderEnabled() throws IOException, ServletException, CertificateException {
        System.setProperty("org.cloudfoundry.router.certificate.header.hide", "true");
        try {
            ClientCertificateMapper mapper = new ClientCertificateMapper();
            this.request.addHeader(ClientCertificateMapper.HEADER, CERTIFICATE_1);
            MockFilterChain chain = new MockFilterChain();
            mapper.doFilter(this.request, this.response, chain);

            HttpServletRequest downstream = (HttpServletRequest) chain.getRequest();
            assertThat(downstream.getHeader(ClientCertificateMapper.HEADER)).isNull();
            assertThat(Collections.list(downstream.getHeaders(ClientCertificateMapper.HEADER))).isEmpty();
            assertThat(Collections.list(downstream.getHeaderNames())).doesNotContain(ClientCertificateMapper.HEADER);
            assertThat((X509Certificate[]) downstream.getAttribute(ClientCertificateMapper.ATTRIBUTE)).hasSize(1);
        } finally {
            System.clearProperty("org.cloudfoundry.router.certificate.header.hide");
        }
    }

    @Test
    public void stripXfccHeaderEnabledByDefault() throws IOException, ServletException {
        this.request.addHeader(ClientCertificateMapper.HEADER, CERTIFICATE_1);
        MockFilterChain chain = new MockFilterChain();
        this.mapper.doFilter(this.request, this.response, chain);

        HttpServletRequest downstream = (HttpServletRequest) chain.getRequest();
        assertThat(downstream.getHeader(ClientCertificateMapper.HEADER)).isNull();
    }

    @Test
    public void stripXfccHeaderExplicitlyDisabled() throws IOException, ServletException, CertificateException {
        System.setProperty("org.cloudfoundry.router.certificate.header.hide", "false");
        try {
            ClientCertificateMapper mapper = new ClientCertificateMapper();
            this.request.addHeader(ClientCertificateMapper.HEADER, CERTIFICATE_1);
            MockFilterChain chain = new MockFilterChain();
            mapper.doFilter(this.request, this.response, chain);

            HttpServletRequest downstream = (HttpServletRequest) chain.getRequest();
            assertThat(downstream.getHeader(ClientCertificateMapper.HEADER)).isNotNull();
        } finally {
            System.clearProperty("org.cloudfoundry.router.certificate.header.hide");
        }
    }

    @Test
    public void stripXfccHeaderNoWrapWhenHeaderAbsent() throws IOException, ServletException, CertificateException {
        System.setProperty("org.cloudfoundry.router.certificate.header.hide", "true");
        try {
            ClientCertificateMapper mapper = new ClientCertificateMapper();
            MockFilterChain chain = new MockFilterChain();
            mapper.doFilter(this.request, this.response, chain);

            assertThat(chain.getRequest()).isSameAs(this.request);
        } finally {
            System.clearProperty("org.cloudfoundry.router.certificate.header.hide");
        }
    }

    @Test
    public void xfccCacheNoCertFieldSkipsCacheLookup() throws IOException, ServletException {
        // A request with only Hash= (no Cert=) must not return a cached cert from a prior request.
        String headerWithCert = "Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b;Cert=" + NGINX_ESCAPED_CERT;
        this.request.addHeader(ClientCertificateMapper.HEADER, headerWithCert);
        this.mapper.doFilter(this.request, this.response, this.filterChain);
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNotNull();

        // Second request: same Hash= but no Cert=
        MockHttpServletRequest request2 = new MockHttpServletRequest();
        request2.addHeader(ClientCertificateMapper.HEADER,
            "Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b");
        this.mapper.doFilter(request2, this.response, new MockFilterChain());

        // Must not return a certificate — Cert= was absent, no cache hit allowed
        assertThat(request2.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
    }

    @Test
    public void stripDateAndIntHeaderHideXfcc() throws IOException, ServletException, CertificateException {
        System.setProperty("org.cloudfoundry.router.certificate.header.hide", "true");
        try {
            ClientCertificateMapper mapper = new ClientCertificateMapper();
            this.request.addHeader(ClientCertificateMapper.HEADER, CERTIFICATE_1);
            MockFilterChain chain = new MockFilterChain();
            mapper.doFilter(this.request, this.response, chain);

            HttpServletRequest downstream = (HttpServletRequest) chain.getRequest();
            assertThat(downstream.getDateHeader(ClientCertificateMapper.HEADER)).isEqualTo(-1);
            assertThat(downstream.getIntHeader(ClientCertificateMapper.HEADER)).isEqualTo(-1);
        } finally {
            System.clearProperty("org.cloudfoundry.router.certificate.header.hide");
        }
    }

    @Test
    public void stripGetHeaderNamesNullSafe() throws IOException, ServletException, CertificateException {
        // Servlet spec permits getHeaderNames() to return null. Wrapping must not throw NPE.
        System.setProperty("org.cloudfoundry.router.certificate.header.hide", "true");
        try {
            ClientCertificateMapper mapper = new ClientCertificateMapper();
            // Use a custom request whose getHeaderNames() returns null
            MockHttpServletRequest nullNamesRequest = new MockHttpServletRequest() {
                @Override
                public java.util.Enumeration<String> getHeaderNames() {
                    return null;
                }
            };
            nullNamesRequest.addHeader(ClientCertificateMapper.HEADER, CERTIFICATE_1);
            MockFilterChain chain = new MockFilterChain();
            mapper.doFilter(nullNamesRequest, this.response, chain);

            HttpServletRequest downstream = (HttpServletRequest) chain.getRequest();
            // Must return null, not throw
            assertThat(downstream.getHeaderNames()).isNull();
        } finally {
            System.clearProperty("org.cloudfoundry.router.certificate.header.hide");
        }
    }

    @Test
    public void cacheSkippedForIdentityOnlyXfccButUsedForCert() throws Exception {
        System.setProperty("org.cloudfoundry.router.certificate.cache.enabled", "true");
        try {
            ClientCertificateMapper mapper = new ClientCertificateMapper();
            CertificateCache cache = mapper.certificateCache();
            assertThat(cache).isNotNull();

            // Identity-only XFCC (Hash+Subject, no Cert=): no certificate to parse, so the cache is bypassed entirely.
            MockHttpServletRequest identityRequest = new MockHttpServletRequest();
            identityRequest.addHeader(ClientCertificateMapper.HEADER,
                "Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b;Subject=\"/CN=client\"");
            mapper.doFilter(identityRequest, new MockHttpServletResponse(), new MockFilterChain());
            assertThat(cache.getMissCount()).isZero();
            assertThat(cache.getHitCount()).isZero();

            // XFCC carrying Cert=: parsed once (miss), then served from the cache (hit).
            String certHeader = "Hash=078c0ea84e084ea1c8bf4719ede79c5b078c0ea84e084ea1c8bf4719ede79c5b;Cert=" + NGINX_ESCAPED_CERT;
            MockHttpServletRequest certRequest1 = new MockHttpServletRequest();
            certRequest1.addHeader(ClientCertificateMapper.HEADER, certHeader);
            mapper.doFilter(certRequest1, new MockHttpServletResponse(), new MockFilterChain());
            assertThat(cache.getMissCount()).isEqualTo(1);
            assertThat(cache.getHitCount()).isZero();

            MockHttpServletRequest certRequest2 = new MockHttpServletRequest();
            certRequest2.addHeader(ClientCertificateMapper.HEADER, certHeader);
            mapper.doFilter(certRequest2, new MockHttpServletResponse(), new MockFilterChain());
            assertThat(cache.getMissCount()).isEqualTo(1);
            assertThat(cache.getHitCount()).isEqualTo(1);
        } finally {
            System.clearProperty("org.cloudfoundry.router.certificate.cache.enabled");
        }
    }
}