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

import static org.assertj.core.api.Assertions.assertThat;

public final class XfccEntryTest {

    @Test
    public void doesNotResembleXfccWithNull() {
        assertThat(new XfccEntry(null).resemblesXfcc()).isFalse();
    }

    @Test
    public void resemblesXfccForEntryStartingWithKnownField() {
        assertThat(new XfccEntry("Hash=abc123;Cert=xyz").resemblesXfcc()).isTrue();
    }

    @Test
    public void doesNotResembleXfccForRawCert() {
        assertThat(new XfccEntry("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A").resemblesXfcc()).isFalse();
    }

    @Test
    public void doesNotResembleXfccForEmptyString() {
        assertThat(new XfccEntry("").resemblesXfcc()).isFalse();
    }

    @Test
    public void getKnownField() {
        XfccEntry entry = new XfccEntry("Hash=abc123def456;Cert=certdata");
        assertThat(entry.get(XfccField.HASH)).isEqualTo("abc123def456");
        assertThat(entry.get(XfccField.CERT)).isEqualTo("certdata");
    }

    @Test
    public void hasFieldReturnsTrueForPresentField() {
        XfccEntry entry = new XfccEntry("Hash=abc;Cert=xyz");
        assertThat(entry.hasField(XfccField.HASH)).isTrue();
        assertThat(entry.hasField(XfccField.CERT)).isTrue();
    }

    @Test
    public void hasFieldReturnsFalseForAbsentField() {
        XfccEntry entry = new XfccEntry("Hash=abc;Cert=xyz");
        assertThat(entry.hasField(XfccField.CHAIN)).isFalse();
        assertThat(entry.hasField(XfccField.SUBJECT)).isFalse();
    }

    @Test
    public void getMissingFieldReturnsNull() {
        XfccEntry entry = new XfccEntry("Hash=abc;Cert=xyz");
        assertThat(entry.get(XfccField.CHAIN)).isNull();
        assertThat(entry.get(XfccField.SUBJECT)).isNull();
    }

    @Test
    public void getQuotedFieldStripsQuotesAndUnescapes() {
        XfccEntry entry = new XfccEntry("Subject=\"/C=US;L=SF\";Cert=xyz");
        assertThat(entry.get(XfccField.SUBJECT)).isEqualTo("/C=US;L=SF");
        assertThat(entry.get(XfccField.CERT)).isEqualTo("xyz");
    }

    @Test
    public void getFieldCaseInsensitive() {
        XfccEntry entry = new XfccEntry("hash=abc123;cert=xyz");
        assertThat(entry.get(XfccField.HASH)).isEqualTo("abc123");
        assertThat(entry.get(XfccField.CERT)).isEqualTo("xyz");
    }

    @Test
    public void fieldNamesListsPresentFields() {
        XfccEntry entry = new XfccEntry("Hash=abc;Cert=xyz");
        assertThat(entry.fieldNames()).isEqualTo("Hash, Cert");
    }

    @Test
    public void fieldNamesEmptyForNonXfcc() {
        assertThat(new XfccEntry("rawcertdata").fieldNames()).isEmpty();
    }

    @Test
    public void unknownFirstFieldIsStillXfcc() {
        XfccEntry entry = new XfccEntry("FutureField=foo;Cert=xyz");
        assertThat(entry.resemblesXfcc()).isTrue();
        assertThat(entry.get(XfccField.CERT)).isEqualTo("xyz");
    }

    @Test
    public void unknownOnlyFieldsNotDetectedAsXfcc() {
        XfccEntry entry = new XfccEntry("FutureField=foo;AnotherNew=bar");
        assertThat(entry.resemblesXfcc()).isFalse();
        assertThat(entry.get(XfccField.CERT)).isNull();
    }

    @Test
    public void malformedTrailingBackslashInQuotedValueDoesNotThrow() {
        // Subject="abc\ — trailing backslash, no closing quote
        XfccEntry entry = new XfccEntry("Hash=abc;Subject=\"abc\\");
        assertThat(entry.resemblesXfcc()).isTrue();
        assertThat(entry.get(XfccField.HASH)).isEqualTo("abc");
        // malformed value: partial content returned, no exception
        assertThat(entry.get(XfccField.SUBJECT)).isNotNull();
    }

    @Test
    public void malformedUnclosedQuoteDoesNotThrow() {
        // Subject=" — quote opened but never closed
        XfccEntry entry = new XfccEntry("Hash=abc;Subject=\"unclosed");
        assertThat(entry.resemblesXfcc()).isTrue();
        assertThat(entry.get(XfccField.HASH)).isEqualTo("abc");
        assertThat(entry.get(XfccField.SUBJECT)).isNotNull();
    }

    @Test
    public void spaceAfterSemicolonDropsField() {
        // Envoy/Gorouter spec does not emit spaces after ';', but document the behaviour
        XfccEntry entry = new XfccEntry("Hash=abc; Cert=xyz");
        assertThat(entry.get(XfccField.HASH)).isEqualTo("abc");
        assertThat(entry.get(XfccField.CERT)).isNull();
    }

    @Test
    public void fieldValueHasNoTrailingSpaceBeforeSemicolon() {
        XfccEntry entry = new XfccEntry("Hash=abc ;Cert=xyz");
        assertThat(entry.get(XfccField.HASH)).isEqualTo("abc ");
        assertThat(entry.get(XfccField.CERT)).isEqualTo("xyz");
    }
}
