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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.SslInfo;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

public class SslInfoRequestDecorator extends ServerHttpRequestDecorator {

	private final Logger logger = LoggerFactory.getLogger(SslInfoRequestDecorator.class);

	private final CertificateLoader certificateLoader;

	private final SslInfo sslInfo;

	public SslInfoRequestDecorator(CertificateLoader certificateLoader, ServerHttpRequest delegate) throws CertificateException, IOException {
		super(delegate);

		this.certificateLoader = certificateLoader;
		final List<String> headers = delegate.getHeaders().get(CertificateLoader.HEADER_NAME);

		if (delegate.getSslInfo() != null || headers == null || headers.isEmpty()) {
			logger.debug("Original request contains SslInfo, skipping certificate loading from header");
			this.sslInfo = delegate.getSslInfo();
		}
		else {
			logger.debug("Original request does not contain SslInfo, loading certificates from header");
			this.sslInfo = new SimpleSslInfoHolder(null, certificateLoader.getCertificates(headers).toArray(new X509Certificate[0]));
		}
	}

	@Override
	public SslInfo getSslInfo() {
		return this.sslInfo;
	}
}
