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

package org.cloudfoundry.router.jakarta;

/**
 * Known field names in an X-Forwarded-Client-Cert (XFCC) header entry.
 * Each constant's {@code key} holds the exact prefix used in the header value (e.g. {@code "Hash="}).
 */
enum XfccField {
    BY("By="),
    HASH("Hash="),
    CERT("Cert="),
    CHAIN("Chain="),
    SUBJECT("Subject="),
    URI("URI="),
    DNS("DNS=");

    final String key;

    XfccField(String key) {
        this.key = key;
    }
}
