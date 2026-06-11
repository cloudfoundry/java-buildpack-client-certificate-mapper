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

package org.cloudfoundry.router.javax;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;
import org.cloudfoundry.router.XfccEntry;
import org.cloudfoundry.router.XfccField;
import org.cloudfoundry.router.XfccHeaderParser;

/**
 * A Servlet {@link Filter} that translates the {@code X-Forwarded-Client} HTTP header to the {@code javax.servlet.request.X509Certificate} Servlet attribute.  This implementation handles both
 * multiple headers as well as the <a href=https://www.rfc-editor.org/rfc/rfc9110#section-5.3>RFC 9110</a> comma delimited equivalent.
 */
final class ClientCertificateMapper implements Filter {

    static final String ATTRIBUTE = "javax.servlet.request.X509Certificate";

    static final String HEADER = "X-Forwarded-Client-Cert";

    /** Request attribute set to the SHA-256 hash from the XFCC {@code Hash=} field, when present. */
    public static final String XFCC_HASH_ATTRIBUTE = "org.cloudfoundry.router.xfcc.hash";

    /** Request attribute set to the subject DN from the XFCC {@code Subject=} field, when present. */
    public static final String XFCC_SUBJECT_ATTRIBUTE = "org.cloudfoundry.router.xfcc.subject";

    /** Request attribute set to the URI SAN from the XFCC {@code URI=} field, when present (e.g. a SPIFFE ID). */
    public static final String XFCC_URI_ATTRIBUTE = "org.cloudfoundry.router.xfcc.uri";

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

    private X509Certificate generateCertificate(String certData) throws CertificateException, IOException {
        try (InputStream in = new ByteArrayInputStream(decodeHeader(certData))) {
            return (X509Certificate) this.certificateFactory.generateCertificate(in);
        }
    }

    private X509Certificate parseCertificate(String rawValue, XfccEntry xfcc) throws CertificateException, IOException {
        if (xfcc.resemblesXfcc()) {
            if (this.logger.isLoggable(java.util.logging.Level.FINE)) {
                this.logger.fine("XFCC entry received with fields: " + xfcc.fieldNames());
            }
            String hash = xfcc.get(XfccField.HASH);
            if (xfcc.hasField(XfccField.HASH) && !XfccHeaderParser.isValidSha256Hex(hash)) {
                this.logger.warning("X-Forwarded-Client-Cert Hash= value does not look like a SHA-256 hex digest");
            }
            if (!xfcc.hasField(XfccField.CERT)) {
                if (xfcc.hasField(XfccField.CHAIN)) {
                    this.logger.warning("X-Forwarded-Client-Cert contains Chain= but no Cert= field; Chain= is not supported and the certificate will not be mapped.");
                }
                return null;
            }
            return generateCertificate(xfcc.get(XfccField.CERT));
        }
        return generateCertificate(rawValue);
    }

    private List<X509Certificate> getCertificates(HttpServletRequest request) throws CertificateException, IOException {
        List<X509Certificate> certificates = new ArrayList<>();

        for (String rawValue : getRawCertificates(request)) {
            XfccEntry xfcc = new XfccEntry(rawValue);
            setXfccAttributes(request, xfcc);
            X509Certificate cert = parseCertificate(rawValue, xfcc);
            if (cert != null) {
                certificates.add(cert);
            }
        }

        return certificates;
    }

    private void setXfccAttributes(HttpServletRequest request, XfccEntry xfcc) {
        if (!xfcc.resemblesXfcc()) {
            return;
        }
        if (request.getAttribute(XFCC_HASH_ATTRIBUTE) == null && xfcc.hasField(XfccField.HASH)) {
            request.setAttribute(XFCC_HASH_ATTRIBUTE, xfcc.get(XfccField.HASH));
        }
        if (request.getAttribute(XFCC_SUBJECT_ATTRIBUTE) == null && xfcc.hasField(XfccField.SUBJECT)) {
            request.setAttribute(XFCC_SUBJECT_ATTRIBUTE, xfcc.get(XfccField.SUBJECT));
        }
        if (request.getAttribute(XFCC_URI_ATTRIBUTE) == null && xfcc.hasField(XfccField.URI)) {
            request.setAttribute(XFCC_URI_ATTRIBUTE, xfcc.get(XfccField.URI));
        }
    }

    private List<String> getRawCertificates(HttpServletRequest request) {
        return XfccHeaderParser.splitHeaderValues(Collections.list(request.getHeaders(HEADER)));
    }

}
