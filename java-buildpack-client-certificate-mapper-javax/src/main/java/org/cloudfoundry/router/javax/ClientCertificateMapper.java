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
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cloudfoundry.router.CertificateCache;
import org.cloudfoundry.router.CfSubjectDn;
import org.cloudfoundry.router.ParsedXfcc;
import org.cloudfoundry.router.XfccAttributes;
import org.cloudfoundry.router.XfccEntry;
import org.cloudfoundry.router.XfccField;
import org.cloudfoundry.router.XfccHeaderParser;
import org.cloudfoundry.router.XfccResolver;

/**
 * A Servlet {@link Filter} that translates the {@code X-Forwarded-Client} HTTP header to the {@code javax.servlet.request.X509Certificate} Servlet attribute.  This implementation handles both
 * multiple headers as well as the <a href=https://tools.ietf.org/html/rfc7230#section-3.2.2>RFC 7230</a> comma delimited equivalent.
 */
final class ClientCertificateMapper implements Filter {

    static final String ATTRIBUTE = "javax.servlet.request.X509Certificate";

    static final String HEADER = "X-Forwarded-Client-Cert";

    private static final String CACHE_ENABLED_PROPERTY = "org.cloudfoundry.router.certificate.cache.enabled";

    private static final String STRIP_HEADER_PROPERTY = "org.cloudfoundry.router.certificate.header.hide";

    private static final String CACHE_SIZE_PROPERTY = "org.cloudfoundry.router.certificate.cache.size";

    private static final int DEFAULT_CACHE_SIZE = 128;

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final XfccResolver resolver;

    /** When {@code true}, the {@code X-Forwarded-Client-Cert} header is hidden from downstream filters after parsing. */
    private final boolean stripXfccHeader;

    ClientCertificateMapper() throws CertificateException {
        boolean cacheEnabled = "true".equalsIgnoreCase(System.getProperty(CACHE_ENABLED_PROPERTY, "false"));
        int cacheSize = DEFAULT_CACHE_SIZE;
        CertificateCache cache = null;
        if (cacheEnabled) {
            String cacheSizeProp = System.getProperty(CACHE_SIZE_PROPERTY);
            if (cacheSizeProp != null) {
                try {
                    cacheSize = Integer.parseInt(cacheSizeProp.trim());
                    if (cacheSize <= 0) {
                        this.logger.warning("Ignoring invalid " + CACHE_SIZE_PROPERTY + " value '" + cacheSizeProp + "'; using default " + DEFAULT_CACHE_SIZE);
                        cacheSize = DEFAULT_CACHE_SIZE;
                    }
                } catch (NumberFormatException e) {
                    this.logger.warning("Ignoring non-numeric " + CACHE_SIZE_PROPERTY + " value '" + cacheSizeProp + "'; using default " + DEFAULT_CACHE_SIZE);
                }
            }
            cache = new CertificateCache(cacheSize);
        }
        this.resolver = new XfccResolver(cache);
        this.stripXfccHeader = "true".equalsIgnoreCase(System.getProperty(STRIP_HEADER_PROPERTY, "true"));
        logConfiguration(cacheEnabled, cacheSize);
    }

    /** Package-private accessor for tests: the certificate cache, or {@code null} when caching is disabled. */
    CertificateCache certificateCache() {
        return this.resolver.cache();
    }

    /** Logs the effective filter configuration once at construction, so operators can confirm which
     *  behaviour is active without having to reason about system property defaults. */
    private void logConfiguration(boolean cacheEnabled, int cacheSize) {
        if (!this.logger.isLoggable(Level.INFO)) {
            return;
        }
        StringBuilder message = new StringBuilder("Mapping ").append(HEADER).append(" to the ").append(ATTRIBUTE).append(" request attribute; certificate cache ");
        if (cacheEnabled) {
            message.append("enabled (").append(CACHE_SIZE_PROPERTY).append('=').append(cacheSize).append(" entries per generation, up to ").append(2 * cacheSize).append(" cached certificates)");
        } else {
            message.append("disabled (").append(CACHE_ENABLED_PROPERTY).append("=true to enable)");
        }
        message.append("; ").append(HEADER).append(" header stripping ");
        if (this.stripXfccHeader) {
            message.append("enabled (header hidden from downstream filters)");
        } else {
            message.append("disabled (").append(STRIP_HEADER_PROPERTY).append("=true to enable)");
        }
        this.logger.info(message.toString());
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
            // IllegalArgumentException: malformed %xx in URL-encoded cert value; treat same as parse failure
            } catch (CertificateException | IllegalArgumentException e) {
                this.logger.warning("Unable to parse certificates in X-Forwarded-Client-Cert");
            }
            // Only wrap when the header is actually present — avoids allocation on requests without a cert.
            if (this.stripXfccHeader && ((HttpServletRequest) request).getHeader(HEADER) != null) {
                request = new XfccStrippingRequestWrapper((HttpServletRequest) request);
            }
        }

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) {

    }

    private List<X509Certificate> getCertificates(HttpServletRequest request) throws CertificateException, IOException {
        List<X509Certificate> certificates = new ArrayList<>();

        for (String rawValue : getRawCertificates(request)) {
            ParsedXfcc parsed = this.resolver.resolve(rawValue);
            setXfccAttributes(request, parsed);
            if (parsed.certificate() != null) {
                certificates.add(parsed.certificate());
            }
        }

        return certificates;
    }

    private void setXfccAttributes(HttpServletRequest request, ParsedXfcc parsed) {
        XfccEntry xfcc = parsed.xfcc();
        if (!xfcc.resemblesXfcc()) {
            return;
        }
        if (request.getAttribute(XfccAttributes.HASH) == null && xfcc.hasField(XfccField.HASH)) {
            request.setAttribute(XfccAttributes.HASH, xfcc.get(XfccField.HASH));
        }
        if (request.getAttribute(XfccAttributes.SUBJECT) == null && xfcc.hasField(XfccField.SUBJECT)) {
            request.setAttribute(XfccAttributes.SUBJECT, xfcc.get(XfccField.SUBJECT));
            setCfSubjectAttributes(request, parsed.cfSubjectDn());
        }
    }

    private void setCfSubjectAttributes(HttpServletRequest request, CfSubjectDn dn) {
        if (dn == null) {
            return;
        }
        if (request.getAttribute(XfccAttributes.APP_GUID) == null && dn.appGuid != null) {
            request.setAttribute(XfccAttributes.APP_GUID, dn.appGuid);
        }
        if (request.getAttribute(XfccAttributes.SPACE_GUID) == null && dn.spaceGuid != null) {
            request.setAttribute(XfccAttributes.SPACE_GUID, dn.spaceGuid);
        }
        if (request.getAttribute(XfccAttributes.ORG_GUID) == null && dn.orgGuid != null) {
            request.setAttribute(XfccAttributes.ORG_GUID, dn.orgGuid);
        }
        if (request.getAttribute(XfccAttributes.INSTANCE_GUID) == null && dn.instanceGuid != null) {
            request.setAttribute(XfccAttributes.INSTANCE_GUID, dn.instanceGuid);
        }
    }

    private List<String> getRawCertificates(HttpServletRequest request) {
        return XfccHeaderParser.splitHeaderValues(Collections.list(request.getHeaders(HEADER)));
    }

    private static final class XfccStrippingRequestWrapper extends HttpServletRequestWrapper {

        XfccStrippingRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getHeader(String name) {
            if (HEADER.equalsIgnoreCase(name)) {
                return null;
            }
            return super.getHeader(name);
        }

        @Override
        public long getDateHeader(String name) {
            if (HEADER.equalsIgnoreCase(name)) {
                return -1;
            }
            return super.getDateHeader(name);
        }

        @Override
        public int getIntHeader(String name) {
            if (HEADER.equalsIgnoreCase(name)) {
                return -1;
            }
            return super.getIntHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if (HEADER.equalsIgnoreCase(name)) {
                return Collections.enumeration(Collections.<String>emptyList());
            }
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            Enumeration<String> orig = super.getHeaderNames();
            if (orig == null) {
                return null;
            }
            List<String> names = Collections.list(orig);
            names.removeIf(name -> HEADER.equalsIgnoreCase(name));
            return Collections.enumeration(names);
        }
    }

}
