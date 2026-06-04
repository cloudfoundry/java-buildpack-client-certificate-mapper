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

    private static final Logger LOGGER = Logger.getLogger(XfccEntry.class.getName());

    private final boolean xfcc;
    private final Map<XfccField, String> fields;

    public XfccEntry(String raw) {
        this.xfcc = isXfccFormat(raw);
        this.fields = xfcc ? parseOnce(raw) : new EnumMap<>(XfccField.class);
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
     * Structural XFCC format check: the entry must start with a short (≤ {@value #MAX_KEY_LENGTH} chars)
     * all-letter key followed by {@code =}. This distinguishes XFCC from raw base64 or PEM certs,
     * whose first {@code =} (base64 padding) appears much later in the string.
     * Note: JSON format (e.g. {@code {"hash":"..."}}) is not supported.
     */
    private static boolean isXfccFormat(String raw) {
        int eq = raw.indexOf('=');
        if (eq <= 0 || eq > MAX_KEY_LENGTH) {
            return false;
        }
        for (int i = 0; i < eq; i++) {
            if (!Character.isLetter(raw.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static Map<XfccField, String> parseOnce(String raw) {
        Map<XfccField, String> result = new EnumMap<>(XfccField.class);
        int len = raw.length();
        int pos = 0;
        while (pos < len) {
            XfccField field = matchField(raw, pos);
            if (field != null) {
                result.put(field, readValue(raw, pos + field.key.length(), len));
            } else if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("X-Forwarded-Client-Cert contains unknown field at position " + pos + " in: " + raw);
            }
            pos = skipToNextField(raw, pos, len);
        }
        return result;
    }

    private static XfccField matchField(String raw, int pos) {
        for (XfccField field : XfccField.values()) {
            if (raw.regionMatches(true, pos, field.key, 0, field.key.length())) {
                return field;
            }
        }
        return null;
    }

    /**
     * Reads a field value starting at {@code start}: strips surrounding quotes and
     * unescapes {@code \"} if quoted, otherwise reads up to the next {@code ;}.
     */
    private static String readValue(String raw, int start, int len) {
        if (start < len && raw.charAt(start) == '"') {
            int end = start + 1;
            while (end < len) {
                char c = raw.charAt(end);
                if (c == '\\') {
                    end += 2;
                } else if (c == '"') {
                    break;
                } else {
                    end++;
                }
            }
            return raw.substring(start + 1, end).replace("\\\"", "\"");
        }
        int semi = raw.indexOf(';', start);
        return raw.substring(start, semi < 0 ? len : semi);
    }

    /**
     * Returns the start position of the next field after the field beginning at {@code pos},
     * correctly skipping over quoted values that may contain {@code ;}.
     */
    private static int skipToNextField(String raw, int pos, int len) {
        int eq = raw.indexOf('=', pos);
        if (eq < 0) {
            return len;
        }
        int valueStart = eq + 1;
        if (valueStart < len && raw.charAt(valueStart) == '"') {
            int i = valueStart + 1;
            while (i < len) {
                char c = raw.charAt(i++);
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    return (i < len && raw.charAt(i) == ';') ? i + 1 : i;
                }
            }
            return len;
        }
        int semi = raw.indexOf(';', valueStart);
        return semi < 0 ? len : semi + 1;
    }
}
