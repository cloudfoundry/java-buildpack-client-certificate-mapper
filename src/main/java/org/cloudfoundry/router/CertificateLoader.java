/*
 * Copyright 2017-2020 the original author or authors.
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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

class CertificateLoader {

    public static final String HEADER_NAME = "X-Forwarded-Client-Cert";
    private final CertificateFactory certificateFactory;

    public CertificateLoader(CertificateFactory certificateFactory) {
        this.certificateFactory = certificateFactory;
    }

    public List<X509Certificate> getCertificates(Iterable<String> headerValues) throws CertificateException, IOException {
        List<X509Certificate> certificates = new ArrayList<>();

        for (String rawCertificate : getRawCertificates(headerValues)) {
            try (InputStream in = new ByteArrayInputStream(decodeHeader(rawCertificate))) {
                certificates.add((X509Certificate) this.certificateFactory.generateCertificate(in));
            }
        }

        return certificates;
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

    private List<String> getRawCertificates(Iterable<String> headerValues) {
        if (headerValues == null) {
            return Collections.emptyList();
        }

        Iterator<String> candidates = headerValues.iterator();
        List<String> rawCertificates = new ArrayList<>();
        while (candidates.hasNext()) {
            String candidate = candidates.next();

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
