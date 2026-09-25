/*
 * Copyright (c) 2026 CodeCatalyst
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codecatalyst.audit;

/**
 * Whether one check ran for one subject (D8). This is what keeps a failed or skipped check from
 * looking like a clean result: zero findings only means "clean" when the matching row says OK.
 *
 * @param subject a host:port, host, or CT domain
 * @param check   {@code ver}, {@code chn02}, {@code caa} or {@code ct}
 * @param status  OK, ERROR or NOT_CHECKED
 * @param message the error exactly as received, or why the check did not run
 */
public record CheckStatus(String subject, String check, Status status, String message) {

    public enum Status { OK, ERROR, NOT_CHECKED }

    public static CheckStatus ok(String subject, String check) {
        return new CheckStatus(subject, check, Status.OK, "");
    }

    public static CheckStatus error(String subject, String check, String message) {
        return new CheckStatus(subject, check, Status.ERROR, message);
    }

    public static CheckStatus notChecked(String subject, String check, String message) {
        return new CheckStatus(subject, check, Status.NOT_CHECKED, message);
    }
}
