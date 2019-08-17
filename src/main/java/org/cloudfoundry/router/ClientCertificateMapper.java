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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
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
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

/**
 * A Servlet {@link Filter} that translates the {@code X-Forwarded-Client} HTTP header to the {@code javax.servlet.request.X509Certificate} Servlet attribute.  This implementation handles both
 * multiple headers as well as the <a href=https://tools.ietf.org/html/rfc7230#section-3.2.2>RFC 7230</a> comma delimited equivalent.
 */
final class ClientCertificateMapper implements Filter {

    private enum CertificateMappingMethod {
        UNKNOWN,
        NGINX,
        GO_ROUTER
    }

    static final String ATTRIBUTE = "javax.servlet.request.X509Certificate";

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
                    request.setAttribute(ATTRIBUTE, certificates.toArray(new X509Certificate[certificates.size()]));
                }
            } catch (CertificateException e) {
                this.logger.warning("Unable to parse certificates in X-Forwarded-Client-Cert");
            }
        }

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    private X509Certificate decodeCertificate(byte[] rawCertificate) throws CertificateException, IOException {        
        try (InputStream in = new ByteArrayInputStream(rawCertificate)) {
            return (X509Certificate) this.certificateFactory.generateCertificate(in);
        } 
    }

    private List<X509Certificate> getCertificates(HttpServletRequest request) throws CertificateException, IOException {
        List<X509Certificate> certificates = new ArrayList<>();

        CertificateMappingMethod certificateMappingMethod = CertificateMappingMethod.UNKNOWN;

        for (String rawCertificate : getRawCertificates(request, HEADER)) {
            if ( CertificateMappingMethod.GO_ROUTER.equals(certificateMappingMethod) || CertificateMappingMethod.UNKNOWN.equals(certificateMappingMethod)) {
                try {
                    certificates.add(decodeCertificate(DatatypeConverter.parseBase64Binary(rawCertificate)));
                    certificateMappingMethod = CertificateMappingMethod.GO_ROUTER;
                } catch (CertificateException | IllegalArgumentException e) {
                    if (certificateMappingMethod != CertificateMappingMethod.UNKNOWN){
                        throw e;
                    }
                }
            }
            if ( CertificateMappingMethod.NGINX.equals(certificateMappingMethod) || CertificateMappingMethod.UNKNOWN.equals(certificateMappingMethod)) {
                try {
                    certificates.add(decodeCertificate(URLDecoder.decode(rawCertificate, "utf-8").getBytes()));
                    certificateMappingMethod = CertificateMappingMethod.NGINX;
                } catch (CertificateException | UnsupportedEncodingException e) {
                    if (certificateMappingMethod != CertificateMappingMethod.UNKNOWN){
                        throw e;
                    }
                }
            }
            if (CertificateMappingMethod.UNKNOWN.equals(certificateMappingMethod)){
                throw new CertificateException();
            }
        }

        return certificates;
    }

    private List<String> getRawCertificates(HttpServletRequest request, String header) {
        Enumeration<String> candidates = request.getHeaders(header);

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
