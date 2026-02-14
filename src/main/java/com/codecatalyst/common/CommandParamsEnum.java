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

package com.codecatalyst.common;

public enum CommandParamsEnum {
    LIST("-list"),
    SCAN("-scan"),
    RANGE("--range"),
    PORT("--ports"),
    REMOVE("-rm"),
    UPDATE("-update"),
    NINJA("-nj"),
    HELP("-help"),
    VERSION("-version");

    private final String param;

    CommandParamsEnum(String param) {
        this.param = param;
    }

    public String getParam() {
        return param;
    }

    public static CommandParamsEnum getEnum(String param) {
        return switch (param) {
            case "-list" -> LIST;
            case "-scan" -> SCAN;
            case "--range" -> RANGE;
            case "-port" -> PORT;
            case "-rm" -> REMOVE;
            case "-update" -> UPDATE;
            case "-nj" -> NINJA;
            case "-help" -> HELP;
            case "-version" -> VERSION;
            default -> throw new IllegalArgumentException("Unknown command parameter: " + param);
        };
    }
}
