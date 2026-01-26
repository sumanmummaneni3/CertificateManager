package com.codecatalyst;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.codecatalyst.net.FetchCertificates;
import com.codecatalyst.persist.PersistenceManager;

import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Objects;

import static com.codecatalyst.CertConstants.DATE_FMT;
import static com.codecatalyst.net.NetUtils.ipToLong;
import static com.codecatalyst.net.NetUtils.longToIp;

/**
 * This is the main for certmgr which is a command line tool
 * that will help user to manage certificates.
 *
 */
//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {

    private static final Logger logger = LogManager.getLogger(Main.class);

    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println(getHelpMessage());
            logger.error(getHelpMessage());
            return;
        }
        String command = args[0];
        try {
            System.out.println("Command: " + command.substring(1));
            switch (command) {
                case "-list":
                    printAllCertificates();
                    break;
                case "-scan":
                    handleScanCommand(args);
                    break;
                case "-rm":
                    removeCertificate(args);
                    break;
                case "-update":
                    updateCertificate(args);
                    break;
                case "-help":
                case "--help":
                    System.out.println(getHelpMessage());
                    break;
                default:
                    String error = "Unknow command "+ command+"\n"+getHelpMessage();
                    logger.error(error);
                    System.err.println(error);
            }
        } catch (Exception e) {
            logger.error("Critical Error: ",e);
        }
    }

    private static void printAllCertificates() throws Exception {
        Map<String, X509Certificate> certs = PersistenceManager.getInstance().getAllCertificates();

        if (certs.isEmpty()) {
            System.out.println("📭 Database is empty.");
            return;
        }

        System.out.printf("%-25s %-30s %-15s%n", "HOST (ALIAS)", "ISSUER", "EXPIRY");
        System.out.println("--------------------------------------------------------------------------");

        for (Map.Entry<String, X509Certificate> entry : certs.entrySet()) {
            X509Certificate cert = entry.getValue();
            String issuer = parseCN(cert.getIssuerX500Principal().getName());

            System.out.printf("%-25s %-30s %-15s%n",
                    truncate(entry.getKey(), 25),
                    truncate(issuer, 30),
                    DATE_FMT.format(cert.getNotAfter())
            );
        }
    }

    private static String parseCN(String dn) {
        if (dn == null) return "";
        for (String part : dn.split(",")) {
            if (part.trim().startsWith("CN=")) return part.trim().substring(3);
        }
        return dn;
    }

    private static String truncate(String s, int len) {
        return (s.length() <= len) ? s : s.substring(0, len - 3) + "...";
    }

    private static void handleScanCommand(String[] args) throws Exception {
        if (args.length > 1 && args[1].equals("--range")) {
            // Range Scan
            String startIp = args[2];
            String endIp   = (args.length == 5) ? args[4] : args[3];

            long start = ipToLong(startIp);
            long end = ipToLong(endIp);

            System.out.println("Scanning Range: " + startIp + " -> " + endIp);
            for (long current = start; current <= end; current++) {
                scanAndStore(longToIp(current));
            }

        } else if (args.length == 2) {
            // Single Scan
            scanAndStore(args[1]);
        } else {
            System.out.println(getHelpMessage());
        }
    }

    private static void scanAndStore(String host) {
        System.out.print("Checking " + host + "... ");
        try {
            X509Certificate cert = new FetchCertificates(host).fetchCertMetadata();
            if (Objects.nonNull(cert)) {
                // DELEGATION: The main class just hands the data to the repository
                PersistenceManager.getInstance().saveCertificate(host, cert);
                System.out.println("Saved.");
                logger.info("Certificate info: " + cert.getIssuerX500Principal().getName());
            } else {
                System.out.println("No SSL.");
                logger.info("SSL Certificate is null !!!");
            }
        } catch (Exception e) {
            logger.error("Critical Error: ",e);
            System.out.println("Error: " + e.getMessage());
        }
    }


    private static boolean isValidIp(String ip) {
        return ip != null && ip.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    }

    private static String getHelpMessage(){
        return """
                
                === CertManager CLI Usage ===
                Usage:
                  1. List DB:         java CertManager -list
                  2. Scan Single:     java CertManager -scan <domain_or_ip>
                  3. Scan Range:      java CertManager -scan --range <start_ip> - <end_ip>
                """;
    }

    private static void removeCertificate(String [] args) throws Exception {
        logger.info("Removing certificate from database...");
        String alias  = args[1];
        logger.info("Removing certificate from database with alias: " + alias);
        PersistenceManager.getInstance().removeCertificate(alias);
    }

    private static void updateCertificate(String [] args) throws Exception {
        if(args.length > 2 && "--host".equals(args[1])){
            String host  = args[2];
            logger.info("Updating certificate from database...");
            scanAndStore(host);
        }
    }
}