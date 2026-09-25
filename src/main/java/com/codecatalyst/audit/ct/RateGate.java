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

package com.codecatalyst.audit.ct;

/**
 * Enforces a minimum interval between live requests, shared by the whole run. crt.sh throttles at
 * 5 requests a minute per source IP (D3 F3), so the audit default is 12.5 s.
 */
public class RateGate {

    private final long intervalNanos;
    private long last = Long.MIN_VALUE;

    public RateGate(long intervalMillis) {
        this.intervalNanos = intervalMillis * 1_000_000L;
    }

    public synchronized void acquire() throws InterruptedException {
        long now = System.nanoTime();
        if (last != Long.MIN_VALUE) {
            long wait = last + intervalNanos - now;
            if (wait > 0) {
                Thread.sleep(wait / 1_000_000L, (int) (wait % 1_000_000L));
                now = System.nanoTime();
            }
        }
        last = now;
    }
}
