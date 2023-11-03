/*
 * Copyright 2017-2019 the original author or authors.
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

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

/**
 * A Servlet {@link Filter} that translates the {@code X-Forwarded-Client} HTTP header to the {@code jakarta.servlet.request.X509Certificate} Servlet attribute.  This implementation handles both
 * multiple headers as well as the <a href=https://tools.ietf.org/html/rfc7230#section-3.2.2>RFC 7230</a> comma delimited equivalent.
 */
final class ClientCertificateMapper implements Filter {

    static final String ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    static final String HEADER = "X-Forwarded-Client-Cert";

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final CertificateFactory certificateFactory;

    ClientCertificateMapper() throws CertificateException {
        this.certificateFactory = CertificateFactory.getInstance("X.509");
    }

    @Override
    public void destroy() {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            try {
                List<X509Certificate> certificates = getCertificates((HttpServletRequest) request);

                if (!certificates.isEmpty()) {
                    request.setAttribute(ATTRIBUTE, certificates.toArray(new X509Certificate[0]));
                }
            } catch (CertificateException e) {
                this.logger.warning("Unable to parse certificates in X-Forwarded-Client-Cert");
            }
        }

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) {

    }

    private byte[] decodeHeader(String rawCertificate) {
        try {
            return Base64.getDecoder().decode(rawCertificate);
        } catch (IllegalArgumentException e1) {
            try {
                return URLDecoder.decode(rawCertificate, "utf-8").getBytes();
            } catch (UnsupportedEncodingException e2) {
                throw new IllegalArgumentException("Header contains value that is neither base64 nor url encoded");
            }
        }
    }

    private List<X509Certificate> getCertificates(HttpServletRequest request) throws CertificateException, IOException {
        List<X509Certificate> certificates = new ArrayList<>();

        for (String rawCertificate : getRawCertificates(request)) {
            try (InputStream in = new ByteArrayInputStream(decodeHeader(rawCertificate))) {
                certificates.add((X509Certificate) this.certificateFactory.generateCertificate(in));
            }
        }

        return certificates;
    }

    private List<String> getRawCertificates(HttpServletRequest request) {
        Enumeration<String> candidates = request.getHeaders(HEADER);

        if (candidates == null) {
            return Collections.emptyList();
        }

        List<String> rawCertificates = new ArrayList<>();
        while (candidates.hasMoreElements()) {
            String candidate = candidates.nextElement();

            if (hasMultipleCertificates(candidate)) {
                rawCertificates.addAll(Arrays.asList(candidate.split(",")));
            } else {
                rawCertificates.add(candidate);
            }
        }

        return rawCertificates;
    }

    private boolean hasMultipleCertificates(String candidate) {
        return candidate.indexOf(',') != -1;
    }

}
