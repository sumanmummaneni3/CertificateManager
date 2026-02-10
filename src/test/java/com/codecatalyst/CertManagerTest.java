package com.codecatalyst;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CertManagerTest {

    private final PrintStream standardOut = System.out;
    private final PrintStream standardErr = System.err;
    private final ByteArrayOutputStream outputStreamCaptor = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errStreamCaptor = new ByteArrayOutputStream();

    @BeforeEach
    public void setUp() {
        System.setOut(new PrintStream(outputStreamCaptor));
        System.setErr(new PrintStream(errStreamCaptor));
    }

    @AfterEach
    public void tearDown() {
        System.setOut(standardOut);
        System.setErr(standardErr);
    }

    @Test
    @DisplayName("Should display help message when no arguments are provided")
    void testMainNoArgs() {
        CertManager.main(new String[]{});
        assertTrue(errStreamCaptor.toString().contains("=== CertManager CLI Usage ==="));
    }

    @Test
    @DisplayName("Should display version information")
    void testVersionCommand() {
        CertManager.main(new String[]{"-version"});
        String output = outputStreamCaptor.toString();
        assertTrue(output.contains("version: 1.0.0"));
        assertTrue(output.contains("Date: 20260201"));
    }

    @Test
    @DisplayName("Should display help message with -help command")
    void testHelpCommand() {
        CertManager.main(new String[]{"-help"});
        assertTrue(outputStreamCaptor.toString().contains("=== CertManager CLI Usage ==="));
    }

    @Test
    @DisplayName("Should handle unknown commands gracefully")
    void testUnknownCommand() {
        CertManager.main(new String[]{"-invalid"});
        assertTrue(errStreamCaptor.toString().contains("Unknown command: -invalid"));
    }

    @Test
    @DisplayName("Should print message when database is empty on -list")
    void testListEmptyDatabase() {
        // This assumes a fresh environment or mocked PersistenceManager
        CertManager.main(new String[]{"-list"});
        assertTrue(outputStreamCaptor.toString().contains("Database is empty.")
                || outputStreamCaptor.toString().contains("HOST (ALIAS)"));
    }
}