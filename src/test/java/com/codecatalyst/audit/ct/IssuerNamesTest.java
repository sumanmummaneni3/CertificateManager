package com.codecatalyst.audit.ct;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IssuerNamesTest {

    @Test
    @DisplayName("crt.sh's reversed, space-separated DN equals Java's RFC 2253 rendering")
    void orderAndSpacing() {
        assertTrue(IssuerNames.same("C=US, O=Let's Encrypt, CN=R11", "CN=R11,O=Let's Encrypt,C=US"));
    }

    @Test
    @DisplayName("Quoted values with commas are parsed, not split")
    void quotedComma() {
        assertTrue(IssuerNames.same("C=US, O=\"DigiCert, Inc.\", CN=DigiCert CA", "CN=DigiCert CA,O=DigiCert\\, Inc.,C=US"));
    }

    @Test
    @DisplayName("Different CNs are different issuers")
    void differentCn() {
        assertFalse(IssuerNames.same("C=US, O=Let's Encrypt, CN=R10", "CN=R11,O=Let's Encrypt,C=US"));
    }

    @Test
    @DisplayName("An attribute Java hex-encodes (emailAddress) is skipped rather than failing the match")
    void hexEncodedAttributeSkipped() {
        assertTrue(IssuerNames.same("emailAddress=ca@example.com, CN=Legacy CA, C=GB",
                "1.2.840.113549.1.9.1=#16106361406578616d706c652e636f6d,CN=Legacy CA,C=GB"));
    }
}
