package com.codecatalyst.net;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class NetUtils {
    public static long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < parts.length; i++) {
            result += (long) (Integer.parseInt(parts[i]) * Math.pow(256, 3 - i));
        }
        return result;
    }

    public static String longToIp(long ip) {
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
    }

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
