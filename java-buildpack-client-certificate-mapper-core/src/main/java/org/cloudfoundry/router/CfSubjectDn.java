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

import java.util.Objects;

/**
 * Parsed CF app identity fields from an XFCC {@code Subject=} DN.
 * CF Gorouter emits: {@code CN=<instance-guid>,OU=app:<app-guid>,OU=space:<space-guid>,OU=organization:<org-guid>}.
 * Fields are {@code null} when the corresponding component is absent.
 */
public final class CfSubjectDn {

    /** App instance GUID from {@code CN=<guid>}. */
    public final String instanceGuid;

    /** CF app GUID from {@code OU=app:<guid>}. */
    public final String appGuid;

    /** CF space GUID from {@code OU=space:<guid>}. */
    public final String spaceGuid;

    /** CF organization GUID from {@code OU=organization:<guid>}. */
    public final String orgGuid;

    public CfSubjectDn(String instanceGuid, String appGuid, String spaceGuid, String orgGuid) {
        this.instanceGuid = instanceGuid;
        this.appGuid = appGuid;
        this.spaceGuid = spaceGuid;
        this.orgGuid = orgGuid;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof CfSubjectDn)) {
            return false;
        }
        CfSubjectDn that = (CfSubjectDn) o;
        return Objects.equals(instanceGuid, that.instanceGuid)
            && Objects.equals(appGuid, that.appGuid)
            && Objects.equals(spaceGuid, that.spaceGuid)
            && Objects.equals(orgGuid, that.orgGuid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(instanceGuid, appGuid, spaceGuid, orgGuid);
    }

    @Override
    public String toString() {
        return "CfSubjectDn{instanceGuid=" + instanceGuid
            + ", appGuid=" + appGuid
            + ", spaceGuid=" + spaceGuid
            + ", orgGuid=" + orgGuid + "}";
    }
}
