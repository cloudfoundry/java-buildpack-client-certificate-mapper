/*
 * Copyright 2017 the original author or authors.
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

import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.ServletException;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

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
    public void noHeader() throws IOException, ServletException {
        this.mapper.doFilter(this.request, this.response, this.filterChain);

        assertThat(this.filterChain.getRequest()).isNotNull();
        assertThat(this.request.getAttribute(ClientCertificateMapper.ATTRIBUTE)).isNull();
    }

}