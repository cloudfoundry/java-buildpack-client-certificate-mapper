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

/**
 * Servlet request attribute names set by the XFCC client certificate mapper.
 */
public final class XfccAttributes {

    /** SHA-256 hash from the XFCC {@code Hash=} field. */
    public static final String HASH    = "org.cloudfoundry.router.xfcc.hash";

    /** Subject DN from the XFCC {@code Subject=} field. */
    public static final String SUBJECT = "org.cloudfoundry.router.xfcc.subject";

    /** CF app GUID from {@code OU=app:<guid>} in the Subject DN. */
    public static final String APP_GUID      = "org.cloudfoundry.router.xfcc.app.guid";

    /** CF space GUID from {@code OU=space:<guid>} in the Subject DN. */
    public static final String SPACE_GUID    = "org.cloudfoundry.router.xfcc.space.guid";

    /** CF organization GUID from {@code OU=organization:<guid>} in the Subject DN. */
    public static final String ORG_GUID      = "org.cloudfoundry.router.xfcc.org.guid";

    /** CF app instance GUID from {@code CN=<guid>} in the Subject DN. */
    public static final String INSTANCE_GUID = "org.cloudfoundry.router.xfcc.instance.guid";

    private XfccAttributes() {
    }
}
