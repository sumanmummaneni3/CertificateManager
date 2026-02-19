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

package com.codecatalyst;

import com.codecatalyst.common.CommandParamsEnum;
import com.codecatalyst.service.NinjaScanner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.codecatalyst.net.FetchCertificates;
import com.codecatalyst.persist.PersistenceManager;

import java.math.BigInteger;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static com.codecatalyst.common.CertConstants.DATE_FMT;
import static com.codecatalyst.net.NetUtils.*;
import static com.codecatalyst.persist.PathManager.getAppHome;

/**
 * This is the main class for Certificate Manager, which is a command line tool
 * that will help the user to manage certificates.
 *
 */
//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class CertManager {

    static {
        initializeLogDir();
    }

    private static final Logger logger = LogManager.getLogger(CertManager.class);
    // Safety limit to prevent accidental scanning of massive IPv6 subnets
    private static final BigInteger MAX_RANGE_SIZE = BigInteger.valueOf(10000);

    public static void main(String[] args) {
        parseAndExecute(args);
    }

    /**
     * Validates the command-line arguments and dispatches to the appropriate handler.
     * Prints a clear error message to {@code stderr} for any invalid or malformed input.
     *
     * @param args the command-line arguments passed to the application
     */
    static void parseAndExecute(String[] args) {
        if (args == null || args.length == 0) {
            System.err.println(getHelpMessage());
            return;
        }

        try {
            CommandParamsEnum command =  CommandParamsEnum.getEnum(args[0]);
            switch (command) {

                case LIST -> printAllCertificates();

                case SCAN -> {
                    if (args.length < 2) {
                        System.err.println("Error: -scan requires a target. Usage: -scan <domain_or_ip> or -scan --range <start_ip> <end_ip>");
                        return;
                    }
                    // Extract --port option from anywhere in the args
                    Set<Integer> ports = extractPorts(args);

                    if ("--range".equals(args[1])) {
                        if (args.length < 4) {
                            System.err.println("Error: --range requires start and end IP. Usage: -scan --range <start_ip> <end_ip>");
                            return;
                        }
                        // Support optional "-" separator: -scan --range <start> - <end>
                        String startIp = args[2];
                        String endIp = (args.length >= 5 && "-".equals(args[3])) ? args[4] : args[3];
                        List<String> hosts = getHostsInRange(startIp, endIp);
                        scanRange(hosts, ports);
                    } else {
                        // Extract host list — supports comma-separated and/or space-separated IPs
                        List<String> hosts = extractHosts(args);
                        if (hosts.isEmpty()) {
                            System.err.println("Error: No valid hosts specified.");
                            return;
                        }
                        for (String host : hosts) {
                            scanAndStore(host, ports);
                        }
                    }
                }

                case REMOVE -> {
                    if (args.length < 2) {
                        System.err.println("Error: -rm requires an alias. Usage: -rm <alias>");
                        return;
                    }
                    removeCertificate(args[1]);
                }

                case UPDATE -> {
                    if (args.length < 3 || !"--host".equals(args[1])) {
                        System.err.println("Error: -update requires a host. Usage: -update --host <domain_or_ip>");
                        return;
                    }
                    updateCertificate(args[2]);
                }

                case HELP -> System.out.println(getHelpMessage());

                case VERSION-> {
                    System.out.println("version: 1.0.0");
                    System.out.println("Date: 20260201");
                }

                case NINJA -> {
                    //We expect -nj -scan  or -nj -scan --range <start_ip> = <end_ip> --port.
                    if (args.length < 2) {
                        System.err.println("Error: Invalid NinjaOne input. Usage: -nj -scan <ip> or -nj -scan --range <start_ip> <end_ip>");
                        return;
                    }
                    if (!"-scan".equals(args[1])) {
                        System.err.println("Error: Unsupported NinjaOne sub-command '" + args[1] + "'. Expected: -scan");
                        return;
                    }
                    handleNinjaOneInput(args);
                }

                default -> {
                    String error = "Unknown command: " + command + "\n" + getHelpMessage();
                    logger.error(error);
                    System.err.println(error);
                }
            }
        } catch (CertificateException e) {
            logger.error("Critical Error: ", e);
            System.err.println("Critical Error: " + e.getMessage());
        }
    }


    private static void handleNinjaOneInput(String[] args) throws CertificateException {
        Set<Integer> ports = extractPorts(args);
        Set<String> hostForScan;
        if ("--range".equals(args[2])) {
            if (args.length < 5) {
                System.err.println("Error: --range requires start and end IP. Usage: -nj -scan --range <start_ip> <end_ip>");
                return;
            }
            List<String> hosts = getHostsInRange(args[3], args[4]);
            scanRange(hosts, ports);
            hostForScan = createHostList(hosts, ports);
        } else {
            // Extract hosts starting from index 2 (after -nj-scan)
            List<String> hosts = extractHosts(args, 2);
            hostForScan = createHostList(hosts, ports);
            if (hosts.isEmpty()) {
                System.err.println("Error: No valid hosts specified.");
                return;
            }
            for (String host : hosts) {
                scanAndStore(host, ports);
            }
        }
        //Fetch the stored data as JSON.
        String result = NinjaScanner.getJSONResults(List.copyOf(hostForScan));
        //For now print this to the console.
        System.out.println(result);
    }

    private static Set<String> createHostList(List<String> hosts, Set<Integer> ports) {
        if(ports.isEmpty() || (ports.size() == 1 && ports.stream().anyMatch(port -> port == 443))) {
            //Do not need any mapping of hosts
            return new HashSet<>(hosts);
        } else {
            Set<String> hostList = new HashSet<>();
            hosts.forEach(host -> ports.forEach(port -> {
                if(port != 443) {
                    String alias = host + "_" + port;
                    hostList.add(alias);
                } else {
                    hostList.add(host);
                }
            }));
            return hostList;
        }
    }
    
    private static void initializeLogDir() {
        Path logPath = getAppHome().resolve("logs");
        try {
            if(!Files.exists(logPath)) {
                Files.createDirectories(logPath);
                Path logFile = logPath.resolve("certmgr.log");
                if(!Files.exists(logFile))
                    Files.createFile(logFile);
            }


        } catch (java.io.IOException e) {
            System.err.println("Could not create log directory: " + e.getMessage());
        }
    }

    private static void printAllCertificates() throws CertificateException {
        Map<String, X509Certificate> certs = Collections.unmodifiableMap(PersistenceManager.getInstance().getAllCertificates());

        if (certs.isEmpty()) {
            System.out.println("Database is empty.");
            return;
        }

        String tableHeader = "%-35s %-25s %-12s %-10s %-12s%n";
        String tableRow    = "%-35s %-25s %-12s %-10s %-12s%n";

        System.out.println("\n--- CERTIFICATE REPOSITORY ---");
        System.out.printf(tableHeader, "HOST (ALIAS)", "ISSUER", "EXPIRY", "DAYS LEFT", "STATUS");
        System.out.println("-".repeat(100));

        for (Map.Entry<String, X509Certificate> entry : certs.entrySet()) {
            X509Certificate cert = entry.getValue();
            String issuer = parseCN(cert.getIssuerX500Principal().getName());
            long daysRemaining =  getDaysRemaining(cert);
            String days = Long.toString(daysRemaining);
            String status = NinjaScanner.getStatus(daysRemaining);

            System.out.printf(tableRow,
                    truncate(entry.getKey(), 40),
                    truncate(issuer, 30),
                    DATE_FMT.format(cert.getNotAfter()),
                    days,
                    status);
        }
    }

    private static long getDaysRemaining(X509Certificate cert) {
        Date expiry = cert.getNotAfter();
        LocalDate expiryDate = expiry.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        LocalDate today = LocalDate.now();
        return ChronoUnit.DAYS.between(today, expiryDate);
    }

    private static String parseCN(String dn) {
        if (dn == null) return "";
        for (String part : dn.split(",")) {
            if (part.trim().startsWith("CN=")) return part.trim().substring(3);
        }
        return dn;
    }

    private static String truncate(String s, int len) {
        if (s == null) return "";
        if (len < 4) return s.substring(0, Math.min(s.length(), len));
        return (s.length() <= len) ? s : s.substring(0, len - 3) + "...";
    }

    /**
     * Scans the arguments' array for a {@code --port} option and parses the port values.
     * <p>Supported formats:</p>
     * <ul>
     *   <li>{@code --port 443}         — single port</li>
     *   <li>{@code --port 80,443,8443} — comma-separated list</li>
     * </ul>
     * If {@code --port} is not present, defaults to port {@code 443}.
     *
     * @param args the full command-line arguments
     * @return an ordered set of port numbers to scan
     */
    public static Set<Integer> extractPorts(String[] args) {
        Set<Integer>  ports = new LinkedHashSet<>();
        int start  = Arrays.asList(args).indexOf("--port");
        if(start >= 0){
            int end  = args.length;
            String [] portsArgs = Arrays.copyOfRange(args, (start+1), end);
            for(String portArg : portsArgs) {
                try {
                    ports.add(parsePorts(portArg));
                } catch (CertificateException e) {
                    // log the message and continue
                    System.err.println(e.getMessage());
                }
            }
            return ports;
        }
        // Default to 443 when --port is not specified
        return Set.of(443);
    }

    /**
     * Extracts host/IP targets from command-line arguments starting after the command flag.
     * Collects all arguments that are not option flags ({@code --port}, {@code --range}, etc.)
     * and splits any comma-separated values into individual hosts.
     * <p>Supported input styles (after shell tokenization):</p>
     * <ul>
     *   <li>{@code -scan 192.168.1.1,192.168.1.2}           — single arg, comma-separated</li>
     *   <li>{@code -scan 192.168.1.1, 192.168.1.2}          — split by shell into two args</li>
     *   <li>{@code -scan 192.168.1.1 192.168.1.2}           — space-separated, no commas</li>
     *   <li>{@code -scan 192.168.1.1, 192.168.1.2 --port 8443} — with trailing options</li>
     * </ul>
     *
     * @param args the full command-line arguments
     * @return list of individual host/IP strings, trimmed and deduplicated in order
     */
    public static List<String> extractHosts(String[] args) {
        return extractHosts(args, 1);
    }

    /**
     * Extracts host/IP targets from command-line arguments starting at the given index.
     *
     * @param args       the full command-line arguments
     * @param startIndex the index to begin scanning for hosts
     * @return list of individual host/IP strings, trimmed and deduplicated in order
     */
    static List<String> extractHosts(String[] args, int startIndex) {
        // Options that signal "stop collecting hosts"
        Set<String> optionFlags = Set.of("--port", "--range");

        LinkedHashSet<String> hosts = new LinkedHashSet<>();

        for (int i = startIndex; i < args.length; i++) {
            String arg = args[i];

            // Stop at known option flags and skip their values
            if (optionFlags.contains(arg)) {
                break;
            }

            // Skip the "-" separator used in range syntax
            if ("-".equals(arg)) {
                continue;
            }

            // Split on commas to handle "ip1,ip2" or "ip1," (trailing comma from shell split)
            String[] parts = arg.split(",");
            for (String part : parts) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    hosts.add(trimmed);
                }
            }
        }

        return new ArrayList<>(hosts);
    }

    /**
     * Parses a comma-separated port string into a validated set of port numbers.
     *
     * @param portValue comma-separated port string, e.g. "443" or "80,443,8443"
     * @return an Integer which is a valid port number
     * @throws CertificateException if any port value is not a valid number or out of range
     */
    public static Integer parsePorts(String portValue) throws CertificateException {
        if(portValue == null || portValue.isBlank() ) {
            throw new CertificateException("Invalid Port value expected an Integer but got null.");
        }
        try {
            int port = Integer.parseInt(portValue);
            if (port < 1 || port > 65535) {
                throw new CertificateException("Port out of range (1-65535): " + port);
            }
            return port;
        } catch (NumberFormatException e) {
            System.err.println("Invalid Port value: " + portValue);
            throw new CertificateException("Invalid Port value: " + portValue);
        }
    }

    private static void scanRange(List<String> hosts, Set<Integer> ports) {
        //Just iterate the list and invoke scan on each host
        for(String host : hosts) {
            scanAndStore(host, ports);
        }
    }

    private static void scanAndStore(String host, Set<Integer> ports) {
        for (int port : ports) {
            String target = (port == 443) ? host : host + ":" + port;
            System.out.print("Checking " + target + "... ");
            try {
                X509Certificate cert = new FetchCertificates(host, port).fetchCertMetadata();
                if (cert != null) {
                    String alias = (port == 443) ? host : host + "_" + port;
                    PersistenceManager.getInstance().saveCertificate(alias, cert);
                    System.out.println("Saved.");
                    logger.info("Certificate info for {}: {}", target, cert.getIssuerX500Principal().getName());
                } else {
                    System.out.println("No SSL.");
                    logger.info("No SSL certificate found on {}", target);
                }
            } catch (Exception e) {
                //logger.error("Error scanning {}: ", target, e);
                System.out.println("Error: " + e.getMessage());
            }
        }
    }

    /**
     * Pure logic to compute a list of IP addresses between two boundaries.
     *
     * @param startIp Starting IP string.
     * @param endIp   Ending IP string.
     * @return List of strings representing the IP range.
     */
    public static List<String> getHostsInRange(String startIp, String endIp) {
        List<String> hosts = new ArrayList<>();
        try {
            BigInteger start = ipToBigInt(startIp);
            BigInteger end = ipToBigInt(endIp);

            // Validation
            if (start.compareTo(end) > 0) {
                logger.error("Invalid Range: Start IP {} is greater than End IP {}.", startIp, endIp);
                return hosts;
            }

            BigInteger size = end.subtract(start).add(BigInteger.ONE);
            if (size.compareTo(MAX_RANGE_SIZE) > 0) {
                logger.error("Range size {} exceeds limit of {}.", size, MAX_RANGE_SIZE);
                return hosts;
            }

            boolean isIPv6 = startIp.contains(":");
            for (BigInteger current = start; current.compareTo(end) <= 0; current = current.add(BigInteger.ONE)) {
                hosts.add(bigIntToIp(current, isIPv6));
            }

        } catch (UnknownHostException e) {
            logger.error("IP Format Error: {}", e.getMessage());
        }
        return hosts;
    }


    private static String getHelpMessage(){
        return """
                
                === CertManager CLI Usage ===
                Usage:
                  1. List DB:          java CertManager -list
                  2. Scan Single:      java CertManager -scan <domain_or_ip>
                  3. Scan Multiple:    java CertManager -scan <ip1> <ip2> <ip3>
                  4. Scan with Port:   java CertManager -scan <domain_or_ip> --port <port>
                  5. Scan with Ports:  java CertManager -scan <ip1> <ip2> --port <port1 port2,...>
                  6. Scan Range:       java CertManager -scan --range <start_ip> <end_ip>
                  7. Range with Port:  java CertManager -scan --range <start_ip> <end_ip> --port <port>
                  8. Remove Cert:      java CertManager -rm <alias>
                  9. Update Cert:      java CertManager -update --host <domain_or_ip>
                 10. Help:             java CertManager -help
                 11. Version:          java CertManager -version
                
                Options:
                  --port <ports>   Comma-separated port(s) to scan (default: 443)
                                   Examples: --port 8443  or  --port 80,443,8443
                """;
    }

    private static void removeCertificate(String alias) throws CertificateException {
        logger.info("Removing certificate from database with alias: {}", alias);
        PersistenceManager.getInstance().removeCertificate(alias);
    }

    private static void updateCertificate(String host) {
        logger.info("Updating certificate for host: {}", host);
        Set<Integer> ports = Set.of(443);
        scanAndStore(host, ports);
    }
}