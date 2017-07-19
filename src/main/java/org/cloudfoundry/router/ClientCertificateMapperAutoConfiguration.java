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

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnCloudPlatform;
import org.springframework.boot.cloud.CloudPlatform;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

import javax.servlet.Filter;
import java.security.cert.CertificateException;

@ConditionalOnClass(Filter.class)
@ConditionalOnCloudPlatform(CloudPlatform.CLOUD_FOUNDRY)
@Configuration
public class ClientCertificateMapperAutoConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    ClientCertificateMapper clientCertificateMapper() throws CertificateException {
        return new ClientCertificateMapper();
    }

}
