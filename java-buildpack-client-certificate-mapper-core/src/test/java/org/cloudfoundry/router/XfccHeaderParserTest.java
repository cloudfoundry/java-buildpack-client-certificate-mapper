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
    public void validateShaWithNull() {
        assertThat(XfccHeaderParser.isValidSha256Hex(null)).isFalse();
    }

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

    @Test
    public void commaInsideQuotedFieldIsNotSplit() {
        List<String> result = XfccHeaderParser.splitHeaderValues(
            Arrays.asList("Hash=abc;Subject=\"/C=US,ST=CA\""));
        assertThat(result).containsExactly("Hash=abc;Subject=\"/C=US,ST=CA\"");
    }

    @Test
    public void commaOutsideQuotedFieldSplitsEntries() {
        List<String> result = XfccHeaderParser.splitHeaderValues(
            Arrays.asList("Hash=abc;Subject=\"/C=US,ST=CA\",Hash=def;Subject=\"/C=DE\""));
        assertThat(result).containsExactly("Hash=abc;Subject=\"/C=US,ST=CA\"", "Hash=def;Subject=\"/C=DE\"");
    }

    @Test
    public void parseCfSubjectDnFullEntry() {
        String subject = "CN=12345678-1234-1234-1234-123456789012," +
            "OU=app:aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb," +
            "OU=space:cccccccc-4444-5555-6666-dddddddddddd," +
            "OU=organization:eeeeeeee-7777-8888-9999-ffffffffffff";
        CfSubjectDn dn = XfccHeaderParser.parseCfSubjectDn(subject);
        assertThat(dn.instanceGuid).isEqualTo("12345678-1234-1234-1234-123456789012");
        assertThat(dn.appGuid).isEqualTo("aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb");
        assertThat(dn.spaceGuid).isEqualTo("cccccccc-4444-5555-6666-dddddddddddd");
        assertThat(dn.orgGuid).isEqualTo("eeeeeeee-7777-8888-9999-ffffffffffff");
    }

    @Test
    public void parseCfSubjectDnPartialEntry() {
        CfSubjectDn dn = XfccHeaderParser.parseCfSubjectDn("CN=some-id");
        assertThat(dn.instanceGuid).isEqualTo("some-id");
        assertThat(dn.appGuid).isNull();
        assertThat(dn.spaceGuid).isNull();
        assertThat(dn.orgGuid).isNull();
    }

    @Test
    public void parseCfSubjectDnNullReturnsNull() {
        assertThat(XfccHeaderParser.parseCfSubjectDn(null)).isNull();
    }

    @Test
    public void parseCfSubjectDnEquality() {
        String subject = "CN=inst,OU=app:a1,OU=space:s1,OU=organization:o1";
        assertThat(XfccHeaderParser.parseCfSubjectDn(subject))
            .isEqualTo(new CfSubjectDn("inst", "a1", "s1", "o1"));
    }

    @Test
    public void parseCfSubjectDnSpacesAroundCommasTrimmed() {
        // Subject value after quote-stripping may have spaces around commas
        String subject = "CN=inst , OU=app:a1 , OU=space:s1 , OU=organization:o1";
        CfSubjectDn dn = XfccHeaderParser.parseCfSubjectDn(subject);
        assertThat(dn.instanceGuid).isEqualTo("inst");
        assertThat(dn.appGuid).isEqualTo("a1");
        assertThat(dn.spaceGuid).isEqualTo("s1");
        assertThat(dn.orgGuid).isEqualTo("o1");
    }

    @Test
    public void parseCfSubjectDnCaseInsensitiveKeys() {
        String subject = "cn=inst,ou=app:a1,OU=SPACE:s1,Ou=Organization:o1";
        CfSubjectDn dn = XfccHeaderParser.parseCfSubjectDn(subject);
        assertThat(dn.instanceGuid).isEqualTo("inst");
        assertThat(dn.appGuid).isEqualTo("a1");
        assertThat(dn.spaceGuid).isEqualTo("s1");
        assertThat(dn.orgGuid).isEqualTo("o1");
    }

    @Test
    public void parseCfSubjectDnEmptyStringReturnsAllNull() {
        CfSubjectDn dn = XfccHeaderParser.parseCfSubjectDn("");
        assertThat(dn.instanceGuid).isNull();
        assertThat(dn.appGuid).isNull();
        assertThat(dn.spaceGuid).isNull();
        assertThat(dn.orgGuid).isNull();
    }

}
