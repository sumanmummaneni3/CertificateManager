package com.codecatalyst.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CsvTargetReaderTest {

    private final CsvTargetReader reader = new CsvTargetReader();

    @Test
    @DisplayName("Columns are matched by name in any order; port defaults to 443; domain, owner and tags are read")
    void allColumns() {
        var r = reader.parse(List.of("Owner,HOST,domain,tags,port",
                "\"Ops, EU\",www.example.com,example.com,env=prod;team=web,",
                "Ops,api.example.com,,,8443"));
        assertEquals(List.of(), r.errors());
        AuditTarget www = r.targets().get(0);
        assertEquals("www.example.com", www.host());
        assertEquals(443, www.port());
        assertEquals("example.com", www.ctDomain());
        assertEquals("DOMAIN", www.ctScope());
        assertEquals("Ops, EU", www.owner());
        assertEquals(Map.of("env", "prod", "team", "web"), www.tags());
        AuditTarget api = r.targets().get(1);
        assertEquals(8443, api.port());
        assertEquals("api.example.com", api.ctDomain());
        assertEquals("HOST_ONLY", api.ctScope());
    }

    @Test
    @DisplayName("A 200-row file with bad rows reports each bad row by line and keeps the rest")
    void rowLevelErrors() {
        List<String> lines = new ArrayList<>(List.of("host,port"));
        for (int i = 0; i < 200; i++) lines.add("h" + i + ".example.com," + (i % 50 == 0 ? "99999" : "443"));
        var r = reader.parse(lines);
        assertEquals(196, r.targets().size());
        assertEquals(List.of(2, 52, 102, 152), r.errors().stream().map(CsvTargetReader.RowError::line).toList());
        assertTrue(r.errors().get(0).reason().contains("Port out of range"));
    }

    @Test
    @DisplayName("A missing header row, or one without 'host', rejects the file with a reason")
    void headerRequired() {
        var r = reader.parse(List.of("www.example.com,443"));
        assertTrue(r.targets().isEmpty());
        assertTrue(r.errors().get(0).reason().contains("'host' column"));
    }

    @Test
    @DisplayName("Duplicate host:port rows are merged and reported, so each is scanned once")
    void duplicates() {
        var r = reader.parse(List.of("host", "WWW.example.com.", "www.example.com"));
        assertEquals(1, r.targets().size());
        assertTrue(r.errors().get(0).reason().startsWith("duplicate of line 2"));
    }

    @Test
    @DisplayName("A host outside its declared domain, a blank host and a malformed tag are row errors")
    void rowValidation() {
        var r = reader.parse(List.of("host,domain,tags", "www.other.com,example.com,", ",example.com,", "a.example.com,,notakeyvalue",
                "\"unterminated,example.com,"));
        assertTrue(r.targets().isEmpty());
        assertEquals(4, r.errors().size());
    }

    @Test
    @DisplayName("Quoted fields with embedded quotes and commas split correctly")
    void quoting() {
        assertEquals(List.of("a", "b,c", "say \"hi\"", ""), CsvTargetReader.splitRow("a,\"b,c\",\"say \"\"hi\"\"\","));
    }
}
