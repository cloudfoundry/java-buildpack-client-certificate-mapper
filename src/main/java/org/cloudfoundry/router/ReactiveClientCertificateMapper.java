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
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.security.cert.CertificateException;

public class ReactiveClientCertificateMapper implements WebFilter {

    private final Logger logger = LoggerFactory.getLogger(ReactiveClientCertificateMapper.class);

    private final CertificateLoader certificateLoader;

    public ReactiveClientCertificateMapper(CertificateLoader certificateLoader) {
        this.certificateLoader = certificateLoader;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        try {
            final SslInfoRequestDecorator requestDecorator = new SslInfoRequestDecorator(this.certificateLoader, exchange.getRequest());
            final ServerWebExchange exchangeWithSslInfo = exchange.mutate().request(requestDecorator).build();
            return chain.filter(exchangeWithSslInfo);
        } catch (CertificateException e) {
            this.logger.warn("Unable to parse certificates in X-Forwarded-Client-Cert");
        } catch (IOException e) {
            return Mono.error(e);
        }

        return chain.filter(exchange);
    }
}
