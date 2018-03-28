/*
 * Copyright 2017-2018 the original author or authors.
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

import org.junit.Test;
import org.springframework.mock.web.MockServletContext;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletException;
import java.util.EnumSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;


public final class ClientCertificateMapperServletContainerInitializerTest {

    private final FilterRegistration.Dynamic dynamic = mock(FilterRegistration.Dynamic.class);

    @Test
    public void onStartup() throws ServletException {
        MockServletContext servletContext = new MockServletContext() {

            @Override
            public FilterRegistration.Dynamic addFilter(String filterName, Filter filter) {
                assertThat(filterName).isEqualTo("clientCertificateMapper");
                assertThat(filter).isInstanceOf(ClientCertificateMapper.class);

                return dynamic;
            }
        };

        new ClientCertificateMapperServletContainerInitializer().onStartup(null, servletContext);

        verify(this.dynamic).addMappingForUrlPatterns(EnumSet.allOf(DispatcherType.class), false, "/*");
    }

    @Test
    public void onStartupNullServletContext() throws ServletException {
        new ClientCertificateMapperServletContainerInitializer().onStartup(null, null);
    }

}