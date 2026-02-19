package com.codecatalyst.service;

import com.codecatalyst.persist.PersistenceManager;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class NinjaScanner {
    private static final ObjectMapper mapper = new ObjectMapper();

//    public static String getJSONResults() throws CertificateException {
//        List<Map<String, Object>> results = new ArrayList<>();
//
//        Map<String, X509Certificate> certificates =  PersistenceManager.getInstance().getAllCertificates();
//        certificates.keySet().forEach(host -> {
//            X509Certificate cert = certificates.get(host);
//            Date expiry = cert.getNotAfter();
//            LocalDate expiryDate = expiry.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
//            results.add(processExpiry(host, expiryDate));
//        });
//
//        try {
//            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(results);
//        } catch (JsonProcessingException e) {
//            return "{\"error\": \"JSON Generation Failed\"}";
//        }
//    }

    public static String getJSONResults(final List<String> alias) throws CertificateException {
        if(alias.isEmpty()){
            return "{\"error\": \"No alias provided\"}";
        } else {
            List<Map<String, Object>> results = new ArrayList<>();
            Map<String, X509Certificate> certificates =  PersistenceManager.getInstance().getAllCertificates();
            for(String host : alias){
                if(certificates.containsKey(host)){
                    X509Certificate cert = certificates.get(host);
                    Date expiry = cert.getNotAfter();
                    LocalDate expiryDate = expiry.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
                    results.add(processExpiry(host, expiryDate));
                }
            }
            try {
                return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(results);
            } catch (JsonProcessingException e) {
                return "{\"error\": \"JSON Generation Failed\"}";
            }
        }
    }

    private static Map<String, Object> processExpiry(String alias, LocalDate expiryDate) {
        LocalDate today = LocalDate.now();
        long daysRemaining = ChronoUnit.DAYS.between(today, expiryDate);

        String status = getStatus(daysRemaining);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("alias", alias);
        result.put("expiryDate", expiryDate.toString());
        result.put("daysRemaining", daysRemaining);
        result.put("status", status);
        return result;
    }

    public static String getStatus(long daysRemaining) {
        String status;
        if (daysRemaining < 0) {
            status = "expired";
        } else if (daysRemaining <= 15) {
            status = "Critical";
        } else if (daysRemaining<=30){
            status = "High";
        } else if(daysRemaining<=60){
            status = "Low";
        } else {
            status = "OK";
        }
        return status;
    }

//    private static Map<String, Object> createErrorResult(String alias, String error) {
//        Map<String, Object> result = new LinkedHashMap<>();
//        result.put("alias", alias);
//        result.put("status", "error");
//        result.put("message", error);
//        return result;
//    }
}