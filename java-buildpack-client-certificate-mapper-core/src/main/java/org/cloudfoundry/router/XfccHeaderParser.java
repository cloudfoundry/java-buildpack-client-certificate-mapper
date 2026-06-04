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
                for (String part : candidate.split(",")) {
                    String trimmed = part.trim();
                    if (!trimmed.isEmpty()) {
                        result.add(trimmed);
                    }
                }
            } else {
                result.add(candidate.trim());
            }
        }
        return result;
    }

    public static boolean isXfccFormat(String value) {
        for (XfccField field : XfccField.values()) {
            if (value.regionMatches(true, 0, field.key, 0, field.key.length())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts a field value from an XFCC entry. Keys are matched case-insensitively.
     * Quoted values (e.g. Subject="/C=US;L=SF") are returned without the surrounding quotes.
     * Semicolons inside double quotes are not treated as field separators.
     */
    public static String extractFieldFromXfcc(String xfccEntry, XfccField field) {
        String fieldPrefix = field.key;
        int start = 0;
        int len = xfccEntry.length();
        while (start < len) {
            int end = findFieldEnd(xfccEntry, start, len);
            if (xfccEntry.regionMatches(true, start, fieldPrefix, 0, fieldPrefix.length())) {
                String value = xfccEntry.substring(start + fieldPrefix.length(), end);
                if (value.length() >= 2 && value.charAt(0) == '"' && value.charAt(value.length() - 1) == '"') {
                    value = value.substring(1, value.length() - 1).replace("\\\"", "\"");
                }
                return value;
            }
            start = end + 1;
        }
        return null;
    }

    /**
     * Returns the end index (exclusive) of the current field starting at {@code start}.
     * Respects double-quoted values so that a {@code ;} inside quotes is not treated as
     * a field separator (e.g. {@code Subject="/C=US;L=SF"}).
     */
    private static int findFieldEnd(String entry, int start, int len) {
        int eq = entry.indexOf('=', start);
        if (eq < 0) return len;
        int valueStart = eq + 1;
        if (valueStart < len && entry.charAt(valueStart) == '"') {
            int i = valueStart + 1;
            while (i < len) {
                char c = entry.charAt(i);
                if (c == '\\') {
                    i += 2;
                } else if (c == '"') {
                    i++;
                    return i;
                } else {
                    i++;
                }
            }
            return len;
        }
        int semi = entry.indexOf(';', valueStart);
        return semi < 0 ? len : semi;
    }

    public static String xfccFieldNames(String xfccEntry) {
        StringBuilder names = new StringBuilder();
        for (XfccField field : XfccField.values()) {
            if (extractFieldFromXfcc(xfccEntry, field) != null) {
                if (names.length() > 0) names.append(", ");
                names.append(field.key, 0, field.key.length() - 1);
            }
        }
        return names.toString();
    }

}
