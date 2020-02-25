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

import org.springframework.http.server.reactive.SslInfo;

import java.security.cert.X509Certificate;

public class SimpleSslInfoHolder implements SslInfo {

	private final String sessionId;
	private final X509Certificate[] peerCertificates;

	public SimpleSslInfoHolder(String sessionId, X509Certificate[] peerCertificates) {
		this.sessionId = sessionId;
		this.peerCertificates = peerCertificates;
	}

	@Override
	public String getSessionId() {
		return this.sessionId;
	}

	@Override
	public X509Certificate[] getPeerCertificates() {
		return this.peerCertificates;
	}
}
