package com.codecatalyst;

import java.text.SimpleDateFormat;

public class CertConstants {
    // Standard PKCS12 format (modern default for Java)
    public static final String KEYSTORE_FILE = "keystore.p12";
    public static final String KEYSTORE_TYPE = "PKCS12";
    public static final char[] PASSWORD = "changeit".toCharArray();
    public static final String DB_FILE = "certificates.csv";
    public static final SimpleDateFormat DATE_FMT = new SimpleDateFormat("yyyy-MM-dd");
}
