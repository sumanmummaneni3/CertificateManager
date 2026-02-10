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
package com.codecatalyst.exception;

/**
 * A custom exception class that can be used for wrapping.
 */
public class CertManagerException extends Exception{

    public CertManagerException(String message) {
        super(message);
    }
    public CertManagerException(String message, Throwable cause) {
        super(message, cause);
    }
    public CertManagerException(Throwable cause) {
        super(cause);
    }
}
