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

package com.codecatalyst.net;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class NetUtils {

    public static BigInteger ipToBigInt(String ipAddress) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ipAddress);
        byte[] bytes = address.getAddress();
        return new BigInteger(1, bytes); // 1 = positive sign
    }

    public static String bigIntToIp(BigInteger bigInt, boolean isV6) throws UnknownHostException {
        byte[] bytes = bigInt.toByteArray();

        // Handle "leading zero" byte issue in BigInteger (sometimes adds an extra byte for sign)
        if (bytes.length > 16 && isV6) {
            bytes = copyOfRange(bytes, bytes.length - 16, bytes.length);
        } else if (bytes.length > 4 && !isV6) {
            bytes = copyOfRange(bytes, bytes.length - 4, bytes.length);
        }
        // Padding: If the number is small (e.g. ::1), BigInt returns only 1 byte.
        // We must pad it back to 4 (v4) or 16 (v6) bytes for InetAddress to recognize it.
        int targetLen = isV6 ? 16 : 4;
        if (bytes.length < targetLen) {
            byte[] padded = new byte[targetLen];
            System.arraycopy(bytes, 0, padded, targetLen - bytes.length, bytes.length);
            bytes = padded;
        }

        return InetAddress.getByAddress(bytes).getHostAddress();
    }

    // Helper for Java 8 compatibility (Arrays.copyOfRange)
    private static byte[] copyOfRange(byte[] original, int from, int to) {
        int newLength = to - from;
        if (newLength < 0) throw new IllegalArgumentException(from + " > " + to);
        byte[] copy = new byte[newLength];
        System.arraycopy(original, from, copy, 0, Math.min(original.length - from, newLength));
        return copy;
    }
}
