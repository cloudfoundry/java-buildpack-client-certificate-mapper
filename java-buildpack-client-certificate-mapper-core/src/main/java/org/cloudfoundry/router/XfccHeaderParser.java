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

    private static final boolean IGNORE_CASE = true;

    private static final String DN_CN_PREFIX = "CN=";
    private static final String DN_OU_APP_PREFIX = "OU=app:";
    private static final String DN_OU_SPACE_PREFIX = "OU=space:";
    private static final String DN_OU_ORG_PREFIX = "OU=organization:";

    private static final int DN_CN_PREFIX_LEN = DN_CN_PREFIX.length();
    private static final int DN_OU_APP_PREFIX_LEN = DN_OU_APP_PREFIX.length();
    private static final int DN_OU_SPACE_PREFIX_LEN = DN_OU_SPACE_PREFIX.length();
    private static final int DN_OU_ORG_PREFIX_LEN = DN_OU_ORG_PREFIX.length();

    private XfccHeaderParser() {
    }

    public static boolean isValidSha256Hex(String value) {
        return value != null && SHA256_HEX.matcher(value).matches();
    }

    /**
     * Parses CF app identity fields from a Subject DN string in a single pass.
     * Returns {@code null} if {@code subject} is {@code null}.
     * Individual fields in the returned object are {@code null} when the corresponding
     * DN component is absent.
     */
    public static CfSubjectDn parseCfSubjectDn(String subject) {
        if (subject == null) {
            return null;
        }
        String instanceGuid = null;
        String appGuid = null;
        String spaceGuid = null;
        String orgGuid = null;
        for (String part : subject.split(",")) {
            String rdn = part.trim();
            String value;
            if ((value = parseGuid(rdn, DN_CN_PREFIX, DN_CN_PREFIX_LEN)) != null) {
                instanceGuid = value;
            } else if ((value = parseGuid(rdn, DN_OU_APP_PREFIX, DN_OU_APP_PREFIX_LEN)) != null) {
                appGuid = value;
            } else if ((value = parseGuid(rdn, DN_OU_SPACE_PREFIX, DN_OU_SPACE_PREFIX_LEN)) != null) {
                spaceGuid = value;
            } else if ((value = parseGuid(rdn, DN_OU_ORG_PREFIX, DN_OU_ORG_PREFIX_LEN)) != null) {
                orgGuid = value;
            }
        }
        return new CfSubjectDn(instanceGuid, appGuid, spaceGuid, orgGuid);
    }

    private static String parseGuid(String rdn, String prefix, int prefixLen) {
        if (rdn.regionMatches(IGNORE_CASE, 0, prefix, 0, prefixLen)) {
            return rdn.substring(prefixLen);
        }
        return null;
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
