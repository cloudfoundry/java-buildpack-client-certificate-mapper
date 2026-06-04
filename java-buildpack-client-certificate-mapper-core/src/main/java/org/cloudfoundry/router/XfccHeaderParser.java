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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

public final class XfccHeaderParser {

    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-fA-F]{64}");

    private XfccHeaderParser() {
    }

    public static boolean isValidSha256Hex(String value) {
        return SHA256_HEX.matcher(value).matches();
    }

    /**
     * Splits comma-delimited HTTP header values (RFC 9110) into individual entries,
     * trimming optional whitespace around each entry and skipping blank values.
     * Commas inside double-quoted field values are not treated as delimiters.
     */
    public static List<String> splitHeaderValues(List<String> headerValues) {
        if (headerValues == null) {
            return Collections.emptyList();
        }

        List<String> result = new ArrayList<>();
        for (String candidate : headerValues) {
            if (candidate == null || candidate.trim().isEmpty()) {
                continue;
            }
            if (candidate.indexOf(',') != -1) {
                splitOnCommasRespectingQuotes(candidate, result);
            } else {
                result.add(candidate.trim());
            }
        }
        return result;
    }

    private static void splitOnCommasRespectingQuotes(String value, List<String> result) {
        int start = 0;
        boolean inQuotes = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' && inQuotes) {
                i++;
            } else if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                String part = value.substring(start, i).trim();
                if (!part.isEmpty()) {
                    result.add(part);
                }
                start = i + 1;
            }
        }
        String last = value.substring(start).trim();
        if (!last.isEmpty()) {
            result.add(last);
        }
    }

}
