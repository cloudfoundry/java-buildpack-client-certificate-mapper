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

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A single parsed X-Forwarded-Client-Cert entry. Parses the raw string in one pass
 * on construction; field values are then available via {@link #get(XfccField)}.
 * An entry is considered XFCC format based on structural detection: a short alphabetic key followed by {@code =}.
 */
public final class XfccEntry {

    /** Maximum expected length of an XFCC field key. Used to distinguish XFCC from raw base64 certs. */
    private static final int MAX_KEY_LENGTH = 20;

    private static final boolean IGNORE_CASE = true;

    private static final XfccField[] FIELDS = XfccField.values();

    private static final Logger LOGGER = Logger.getLogger(XfccEntry.class.getName());

    private final boolean xfcc;
    private final Map<XfccField, String> fields;

    public XfccEntry(String raw) {
        this.xfcc = isXfccFormat(raw);
        this.fields = xfcc ? parseOnce(raw) : Collections.emptyMap();
    }

    /** Returns true if the entry is XFCC format and contains at least one of Hash=, Cert=, or Chain=. */
    public boolean resemblesXfcc() {
        return xfcc && (hasField(XfccField.HASH) || hasField(XfccField.CERT) || hasField(XfccField.CHAIN));
    }

    /** Returns the value of the given field, or {@code null} if absent. */
    public String get(XfccField field) {
        return fields.get(field);
    }

    /** Returns true if the given field is present in this entry. */
    public boolean hasField(XfccField field) {
        return fields.containsKey(field);
    }

    /** Returns a comma-separated list of known field names present in this entry, in declaration order. */
    public String fieldNames() {
        StringBuilder names = new StringBuilder();
        for (XfccField field : XfccField.values()) {
            if (fields.containsKey(field)) {
                if (names.length() > 0) {
                    names.append(", ");
                }
                names.append(field.key, 0, field.key.length() - 1);
            }
        }
        return names.toString();
    }

    /**
     * Structural XFCC format check: scans at most {@value #MAX_KEY_LENGTH} characters looking for
     * an all-letter key followed by {@code =}. Stops early on any non-letter, non-{@code =} character.
     * This is O(1) and avoids scanning the full string for raw base64/PEM certs.
     * Note: JSON format (e.g. {@code {"hash":"..."}}) is not supported.
     */
    private static boolean isXfccFormat(String raw) {
        if (raw == null || raw.isEmpty()) {
            return false;
        }

        int limit = Math.min(raw.length(), MAX_KEY_LENGTH + 1);
        for (int i = 0; i < limit; i++) {
            char c = raw.charAt(i);
            if (c == '=') {
                return i > 0;
            }
            if (!Character.isLetter(c)) {
                return false;
            }
        }

        return false;
    }

    private static Map<XfccField, String> parseOnce(String raw) {
        Map<XfccField, String> result = new EnumMap<>(XfccField.class);
        int len = raw.length();
        int pos = 0;
        while (pos < len) {
            XfccField field = matchField(raw, pos);
            if (field != null) {
                result.put(field, readValue(raw, pos + field.keyLength, len));
            } else if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("X-Forwarded-Client-Cert contains unknown field at position " + pos);
            }
            pos = skipToNextField(raw, pos, len);
        }
        return result;
    }

    private static XfccField matchField(String raw, int pos) {
        for (XfccField field : FIELDS) {
            if (raw.regionMatches(IGNORE_CASE, pos, field.key, 0, field.keyLength)) {
                return field;
            }
        }
        return null;
    }

    /**
     * Reads a field value starting at {@code start}: strips surrounding quotes and
     * unescapes {@code \"} if quoted, otherwise reads up to the next {@code ;}.
     * Malformed input (unclosed quote, trailing backslash) is handled gracefully.
     */
    private static String readValue(String raw, int start, int len) {
        if (start < len && raw.charAt(start) == '"') {
            int end = start + 1;
            while (end < len) {
                char c = raw.charAt(end);
                if (c == '\\') {
                    end = Math.min(end + 2, len);
                } else if (c == '"') {
                    break;
                } else {
                    end++;
                }
            }
            return raw.substring(start + 1, Math.min(end, len)).replace("\\\"", "\"");
        }
        int semi = raw.indexOf(';', start);
        return raw.substring(start, semi < 0 ? len : semi);
    }

    /**
     * Returns the start position of the next field after the field beginning at {@code pos},
     * correctly skipping over quoted values that may contain {@code ;}.
     * Malformed input (unclosed quote, trailing backslash) is handled gracefully.
     */
    private static int skipToNextField(String raw, int pos, int len) {
        int eq = raw.indexOf('=', pos);
        if (eq < 0) {
            return len;
        }
        int valueStart = eq + 1;
        Integer i = findStartOfNextFieldAfterQuotedValue(raw, len, valueStart);
        if (i != null) {
            return i;
        }
        int semi = raw.indexOf(';', valueStart);
        return semi < 0 ? len : semi + 1;
    }

    /**
     * If the value at {@code valueStart} is quoted, returns the index where parsing should
     * continue for the next field; otherwise returns {@code null}.
     *
     * <p>For quoted values, this method scans until the closing quote while honoring escaped
     * characters (e.g. {@code \"}). If the closing quote is followed by {@code ;}, the
     * returned index is just after that separator; otherwise it is the character immediately
     * after the closing quote. Malformed input (unclosed quote) returns {@code len}.
     */
    private static Integer findStartOfNextFieldAfterQuotedValue(String raw, int len, int valueStart) {
        if (valueStart < len && raw.charAt(valueStart) == '"') {
            int i = valueStart + 1;
            while (i < len) {
                char c = raw.charAt(i++);
                if (c == '\\') {
                    i = Math.min(i + 1, len);
                } else if (c == '"') {
                    return (i < len && raw.charAt(i) == ';') ? i + 1 : i;
                }
            }
            return len;
        }
        return null;
    }
}
