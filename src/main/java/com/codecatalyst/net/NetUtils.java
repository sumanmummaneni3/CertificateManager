package com.codecatalyst.net;

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
}
