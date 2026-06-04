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
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

/**
 * A Servlet {@link Filter} that translates the {@code X-Forwarded-Client} HTTP header to the {@code javax.servlet.request.X509Certificate} Servlet attribute.  This implementation handles both
 * multiple headers as well as the <a href=https://tools.ietf.org/html/rfc7230#section-3.2.2>RFC 7230</a> comma delimited equivalent.
 */
final class ClientCertificateMapper implements Filter {

    static final String ATTRIBUTE = "javax.servlet.request.X509Certificate";

    static final String HEADER = "X-Forwarded-Client-Cert";

    private static final List<String> XFCC_KEYS = Arrays.asList("By=", "Hash=", "Cert=", "Chain=", "Subject=", "URI=", "DNS=");

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

    private boolean isXfccFormat(String value) {
        for (String key : XFCC_KEYS) {
            if (value.regionMatches(true, 0, key, 0, key.length())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts a field value from an XFCC entry. Keys are matched case-insensitively.
     * Quoted values (e.g. Subject="/C=US;L=SF") are returned without the surrounding quotes.
     * Extracts a field value from an XFCC entry. Keys are matched case-insensitively.
     * Quoted values (e.g. Subject="/C=US;L=SF") are returned without the surrounding quotes.
     * Semicolons inside double quotes are not treated as field separators.
     */
    private String extractFieldFromXfcc(String xfccEntry, String fieldPrefix) {
        int start = 0;
        int len = xfccEntry.length();
        while (start < len) {
            int end = findFieldEnd(xfccEntry, start, len);
            if (xfccEntry.regionMatches(true, start, fieldPrefix, 0, fieldPrefix.length())) {
                String value = xfccEntry.substring(start + fieldPrefix.length(), end);
                if (value.length() >= 2 && value.charAt(0) == '"' && value.charAt(value.length() - 1) == '"') {
                    value = value.substring(1, value.length() - 1).replace("\\\"", "\"");
                }
                return value;
            }
            start = end + 1;
        }
        return null;
    }

    /**
     * Returns the end index (exclusive) of the current field starting at {@code start}.
     * Respects double-quoted values so that a {@code ;} inside quotes is not treated as
     * a field separator (e.g. {@code Subject="/C=US;L=SF"}).
     */
    private int findFieldEnd(String entry, int start, int len) {
        int eq = entry.indexOf('=', start);
        if (eq < 0) return len;
        int valueStart = eq + 1;
        if (valueStart < len && entry.charAt(valueStart) == '"') {
            int i = valueStart + 1;
            while (i < len) {
                char c = entry.charAt(i);
                if (c == '\\') {
                    i += 2;
                } else if (c == '"') {
                    i++;
                    return i; // end is after closing quote
                } else {
                    i++;
                }
            }
            return len;
        }
        int semi = entry.indexOf(';', valueStart);
        return semi < 0 ? len : semi;
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

    private String xfccFieldNames(String xfccEntry) {
        StringBuilder names = new StringBuilder();
        for (String key : XFCC_KEYS) {
            if (extractFieldFromXfcc(xfccEntry, key) != null) {
                if (names.length() > 0) names.append(", ");
                names.append(key, 0, key.length() - 1); // strip trailing '='
            }
        }
        return names.toString();
    }

    private static final java.util.regex.Pattern SHA256_HEX = java.util.regex.Pattern.compile("[0-9a-fA-F]{64}");

    private X509Certificate parseCertificate(String rawValue) throws CertificateException, IOException {
        if (isXfccFormat(rawValue)) {
            if (this.logger.isLoggable(java.util.logging.Level.FINE)) {
                this.logger.fine("XFCC entry received with fields: " + xfccFieldNames(rawValue));
            }
            String hash = extractFieldFromXfcc(rawValue, "Hash=");
            if (hash != null && !SHA256_HEX.matcher(hash).matches()) {
                this.logger.warning("X-Forwarded-Client-Cert Hash= value does not look like a SHA-256 hex digest: " + hash);
            }
            String certData = extractFieldFromXfcc(rawValue, "Cert=");
            if (certData == null) {
                if (extractFieldFromXfcc(rawValue, "Chain=") != null) {
                    this.logger.warning("X-Forwarded-Client-Cert contains Chain= but no Cert= field; Chain= is not supported and the certificate will not be mapped.");
                }
                return null;
            }
            return generateCertificate(certData);
        }
        return generateCertificate(rawValue);
    }

    private List<X509Certificate> getCertificates(HttpServletRequest request) throws CertificateException, IOException {
        List<X509Certificate> certificates = new ArrayList<>();

        for (String rawValue : getRawCertificates(request)) {
            X509Certificate cert = parseCertificate(rawValue);
            if (cert != null) {
                certificates.add(cert);
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

            if (candidate == null || candidate.isEmpty()) {
                continue;
            }

            if (hasMultipleCertificates(candidate)) {
                for (String part : candidate.split(",")) {
                    if (!part.isEmpty()) {
                        rawCertificates.add(part);
                    }
                }
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
