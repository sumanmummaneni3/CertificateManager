package com.codecatalyst.service;

import com.codecatalyst.persist.PersistenceManager;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class NinjaScanner {
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    public static String getJSONResults() throws CertificateException {
        List<Map<String, Object>> results = new ArrayList<>();

        Map<String, X509Certificate> certificates =  PersistenceManager.getInstance().getAllCertificates();
        certificates.keySet().forEach(host -> {
            X509Certificate cert = certificates.get(host);
            Date expiry = cert.getNotAfter();
            LocalDate expiryDate = expiry.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
            results.add(processExpiry(host, expiryDate));
        });

//        for (String line : lines) {
//            String[] parts = line.split(",");
//            if (parts.length < 2) continue;
//
//            String alias = parts[0].trim();
//            String expiryStr = parts[1].trim();
//
//            try {
//                LocalDate expiryDate = LocalDate.parse(expiryStr, formatter);
//                results.add(processExpiry(alias, expiryDate));
//            } catch (Exception e) {
//                results.add(createErrorResult(alias, "Invalid Date Format"));
//            }
//        }

        try {
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(results);
        } catch (JsonProcessingException e) {
            return "{\"error\": \"JSON Generation Failed\"}";
        }
    }

    private static Map<String, Object> processExpiry(String alias, LocalDate expiryDate) {
        LocalDate today = LocalDate.now();
        long daysRemaining = ChronoUnit.DAYS.between(today, expiryDate);

        String status;
        if (daysRemaining < 0) {
            status = "expired";
        } else if (daysRemaining <= 30) {
            status = "expiring in " + daysRemaining + " days";
        } else {
            status = "OK";
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("alias", alias);
        result.put("expiryDate", expiryDate.toString());
        result.put("daysRemaining", daysRemaining);
        result.put("status", status);
        return result;
    }

    private static Map<String, Object> createErrorResult(String alias, String error) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("alias", alias);
        result.put("status", "error");
        result.put("message", error);
        return result;
    }
}