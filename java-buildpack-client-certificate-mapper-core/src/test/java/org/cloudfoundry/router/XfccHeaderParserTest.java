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

package org.cloudfoundry.router;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public final class XfccHeaderParserTest {

    @Test
    public void splitSingleValue() {
        List<String> result = XfccHeaderParser.splitHeaderValues(
            Arrays.asList("By=spiffe://test;Cert=abc"));
        assertThat(result).containsExactly("By=spiffe://test;Cert=abc");
    }

    @Test
    public void splitSingleValueWithLeadingWhitespace() {
        List<String> result = XfccHeaderParser.splitHeaderValues(
            Arrays.asList(" By=spiffe://test;Cert=abc"));
        assertThat(result).containsExactly("By=spiffe://test;Cert=abc");
    }

    @Test
    public void splitCommaSeparatedValues() {
        List<String> result = XfccHeaderParser.splitHeaderValues(
            Arrays.asList("By=a;Cert=x,By=b;Cert=y"));
        assertThat(result).containsExactly("By=a;Cert=x", "By=b;Cert=y");
    }

    @Test
    public void splitCommaSeparatedValuesWithWhitespace() {
        List<String> result = XfccHeaderParser.splitHeaderValues(
            Arrays.asList("By=a;Cert=x , By=b;Cert=y"));
        assertThat(result).containsExactly("By=a;Cert=x", "By=b;Cert=y");
    }

    @Test
    public void skipNullAndEmptyValues() {
        List<String> result = XfccHeaderParser.splitHeaderValues(
            Arrays.asList("", "By=a;Cert=x", "  "));
        assertThat(result).containsExactly("By=a;Cert=x");
    }

    @Test
    public void multipleHeaderValues() {
        List<String> result = XfccHeaderParser.splitHeaderValues(
            Arrays.asList("By=a;Cert=x", " By=b;Cert=y"));
        assertThat(result).containsExactly("By=a;Cert=x", "By=b;Cert=y");
    }

}
