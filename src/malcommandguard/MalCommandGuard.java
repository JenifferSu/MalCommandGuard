/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package malcommandguard;

import java.io.Console;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.Scanner;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;
import java.security.MessageDigest;
import java.util.*;
import java.net.http.*;
import java.net.URI;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

/**
 *
 * @author User
 */
public class MalCommandGuard {

    private static final Logger logger = Logger.getLogger(MalCommandGuard.class.getName());
    private static Scanner scanner = new Scanner(System.in);
    private static UserManager userManager = new UserManager();
    private static CommandAnalyzer analyzer = new CommandAnalyzer();
    private static User currentUser = null;
    private static final int MAX_ATTEMPTS = 3;
    private static FileHandler fileHandler; // Correct type declaration
    
    public static void main(String[] args) {
        setupLogging();
        printWelcomeBanner();
        
        // Authentication process
        if (authenticateUser()) {
            runMainLoop();
        } else {
            System.out.println("[ERROR] Authentication failed. Exiting...");
            logger.severe("Authentication failed - system exit");
        }
        
        scanner.close();
        
        // Properly close logging to ensure file is accessible
        if (fileHandler != null) {
            fileHandler.close();
        }
        
        logger.info("Application terminated");
    }
    
    private static void setupLogging() {
        try {
            FileHandler fileHandler = new FileHandler("malcommandguard.log", true);
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
            logger.setUseParentHandlers(true);
            logger.info("=== MalCommandGuard CLI Started ===");
        } catch (IOException e) {
            System.err.println("[WARNING] Could not setup file logging: " + e.getMessage());
        }
    }
    
    private static void printWelcomeBanner() {
        System.out.println("\n" + "=".repeat(70));
        System.out.println("MALCOMMANDGUARD");
        System.out.println("Advanced Command & URL Detection System");
        System.out.println("=".repeat(70));
        System.out.println("Detection Method: Rule-based Detection");
        System.out.println("=".repeat(70));
    }
    
    private static boolean authenticateUser() {
        while (true) {
            System.out.println("\nAUTHENTICATION MENU");
            System.out.println("-".repeat(30));
            System.out.println("1. Login");
            System.out.println("2. Register New User");
            System.out.println("3. Exit");
            System.out.print("Choose option (1-3): ");
            
            String choice = scanner.nextLine().trim();
            
            switch (choice) {
                case "1":
                    if (performLogin()) return true;
                    break;
                case "2":
                    performRegistration();
                    break;
                case "3":
                    System.out.println("Goodbye!");
                    return false;
                default:
                    System.out.println("[ERROR] Invalid option. Please try again.");
            }
        }
    }
    
    private static boolean performLogin() {
        System.out.println("\nSECURE LOGIN");
        System.out.println("-".repeat(20));
        System.out.println("[SECURITY] Maximum 3 login attempts allowed");
        System.out.println("[WARNING] Program will exit after 3 failed attempts");
        System.out.println("[INFO] Password input will use secure GUI dialog");
        
        int attempts = 0;
        while (attempts < MAX_ATTEMPTS) {
            System.out.print("Username: ");
            String username = scanner.nextLine().trim();
            
            // Input validation for username
            if (!isValidUsername(username)) {
                System.out.println("[ERROR] Invalid username format!");
                attempts++;
                continue;
            }
            
            System.out.print("Password: ");
            String password = readPasswordSecurely();
            
            // Input validation for password
            if (password.isEmpty()) {
                System.out.println("[ERROR] Password cannot be empty!");
                attempts++;
                continue;
            }
            
            // Authenticate
            currentUser = userManager.authenticate(username, password);
            if (currentUser != null) {
                System.out.println("[SUCCESS] Login successful!");
                System.out.println("Welcome " + currentUser.getUsername() + 
                                 " (Role: " + currentUser.getRole() + ")");
                logger.info("User logged in: " + username + " (" + currentUser.getRole() + ")");
                return true;
            } else {
                attempts++;
                int remaining = MAX_ATTEMPTS - attempts;
                System.out.println("[ERROR] Invalid credentials! Attempts remaining: " + remaining);
                logger.warning("Failed login attempt for: " + username);
                
                if (remaining == 0) {
                    System.out.println("[SECURITY LOCKOUT] Too many failed attempts!");
                    System.out.println("[SYSTEM] Program will now exit for security reasons.");
                    System.out.println("[INFO] This is a security feature - not an error.");
                    logger.severe("Security lockout triggered after " + MAX_ATTEMPTS + " failed attempts - System exit");
                    
                    // Close scanner before exit
                    scanner.close();
                    
                    // Properly close logging to ensure file is accessible
                    if (fileHandler != null) {
                        fileHandler.close();
                    }
                    
                    // Wait 3 seconds before exit to let user read the message
                    try {
                        System.out.println("\nExiting in 3 seconds...");
                        Thread.sleep(3000);
                    } catch (InterruptedException e) {
                        // Ignore interruption
                    }
                    
                    // Exit with code 0 to avoid "BUILD FAILED" in NetBeans
                    // but log it as a security exit
                    System.out.println("Program terminated for security reasons.");
                    System.exit(0);
                }
            }
        }
        return false;
    }
    
    private static void performRegistration() {
        System.out.println("\nUSER REGISTRATION");
        System.out.println("-".repeat(25));
        System.out.println("[INFO] Password input will use secure GUI dialog");
        System.out.println("[SECURITY] New users are automatically assigned USER role");
        
        String username;
        while (true) {
            System.out.print("Enter username (3-20 characters, alphanumeric): ");
            username = scanner.nextLine().trim();
            
            if (!isValidUsername(username)) {
                System.out.println("[ERROR] Username must be 3-20 characters, alphanumeric only!");
                continue;
            }
            
            if (userManager.userExists(username)) {
                System.out.println("[ERROR] Username already exists!");
                continue;
            }
            
            break;
        }
        
        String password;
        while (true) {
            System.out.print("Enter password (minimum 8 characters): ");
            password = readPasswordSecurely();
            
            if (!isValidPassword(password)) {
                System.out.println("[ERROR] Password must be at least 8 characters!");
                continue;
            }
            
            System.out.print("Confirm password: ");
            String confirmPassword = readPasswordSecurely();
            
            if (!password.equals(confirmPassword)) {
                System.out.println("[ERROR] Passwords do not match!");
                continue;
            }
            
            break;
        }
        
        System.out.print("Enter role (USER/ADMIN) [default: USER]: ");
        String role = scanner.nextLine().trim().toUpperCase();
        if (role.isEmpty()) role = "USER";
        
        if (!role.equals("USER") && !role.equals("ADMIN")) {
            role = "USER";
            System.out.println("[INFO] Invalid role specified. Defaulting to USER.");
        }
        
        if (userManager.registerUser(username, password, role)) {
            System.out.println("[SUCCESS] User registered successfully!");
            logger.info("New user registered: " + username + " (" + role + ")");
        } else {
            System.out.println("[ERROR] Registration failed!");
            logger.severe("Registration failed for: " + username);
        }
    }
    
    private static boolean isValidUsername(String username) {
        if (username == null || username.length() < 3 || username.length() > 20) {
            return false;
        }
        return Pattern.matches("^[a-zA-Z0-9]+$", username);
    }
    
    private static boolean isValidPassword(String password) {
        return password != null && password.length() >= 8;
    }
    
    /**
     * Securely reads password input with masking
     * Uses GUI dialog in IDE environments, console masking in terminal
     */
    private static String readPasswordSecurely() {
        Console console = System.console();
        if (console != null) {
            // Use Console for password masking in terminal/command prompt
            char[] passwordChars = console.readPassword();
            String password = new String(passwordChars);
            
            // Clear the password from memory for security
            java.util.Arrays.fill(passwordChars, '\0');
            
            return password;
        } else {
            // Use GUI password dialog in IDE environments like NetBeans
            try {
                javax.swing.JPasswordField passwordField = new javax.swing.JPasswordField(20);
                passwordField.setEchoChar('*'); // Mask with asterisks
                
                int result = javax.swing.JOptionPane.showConfirmDialog(
                    null,
                    passwordField,
                    "Enter Password (Secure Input)",
                    javax.swing.JOptionPane.OK_CANCEL_OPTION,
                    javax.swing.JOptionPane.PLAIN_MESSAGE
                );
                
                if (result == javax.swing.JOptionPane.OK_OPTION) {
                    String password = new String(passwordField.getPassword());
                    
                    // Clear password field for security
                    passwordField.setText("");
                    
                    System.out.println("[SECURITY] Password entered securely via GUI");
                    return password;
                } else {
                    System.out.println("[INFO] Password input cancelled");
                    return "";
                }
            } catch (Exception e) {
                // Final fallback to regular input with warning
                System.out.print("[WARNING: Password will be visible] Enter password: ");
                return scanner.nextLine().trim();
            }
        }
    }
    
    private static void runMainLoop() {
        System.out.println("\n[INFO] Database loaded: " + analyzer.getDatabaseSize() + " command entries");
        System.out.println("[INFO] System ready for command analysis!");
        
        while (true) {
            showMainMenu();
            String choice = scanner.nextLine().trim();
            
            switch (choice.toLowerCase()) {
                case "1":
                case "analyze":
                    analyzeCommand();
                    break;
                case "2":
                case "stats":
                    showStatistics();
                    break;
                case "3":
                case "admin":
                    if (currentUser.isAdmin()) {
                        adminMenu();
                    } else {
                        System.out.println("[ACCESS DENIED] Admin privileges required.");
                        logger.warning("Unauthorized admin access attempt by: " + currentUser.getUsername());
                    }
                    break;
                case "4":
                case "help":
                    showHelp();
                    break;
                case "5":
                case "logout":
                    logger.info("User logged out: " + currentUser.getUsername());
                    currentUser = null;
                    System.out.println("[INFO] Logged out successfully.");
                    if (authenticateUser()) continue;
                    else return;
                case "6":
                case "exit":
                case "quit":
                    System.out.println("Goodbye! Stay secure!");
                    return;
                case "7":
                case "virustotal":
                    VirusTotalIntegration vtIntegration = new VirusTotalIntegration();
                    vtIntegration.executeVirusTotalAnalysis(scanner);
                    break;
                default:
                    System.out.println("[ERROR] Invalid option. Please try again.");
            }
        }
    }
    
    private static void showMainMenu() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("MAIN MENU - " + currentUser.getUsername() + " (" + currentUser.getRole() + ")");
        System.out.println("=".repeat(60));
        System.out.println("1. Analyze Command/URL");
        System.out.println("2. View Statistics");
        if (currentUser.isAdmin()) {
            System.out.println("3. Admin Panel");
        }
        System.out.println("4. Help");
        System.out.println("5. Logout");
        System.out.println("6. Exit");
        System.out.println("7. VirusTotal Analysis");
        System.out.println("-".repeat(60));
        System.out.print("Select option: ");
    }
    
    private static void analyzeCommand() {
        System.out.println("\nCOMMAND/URL ANALYSIS MODULE");
        System.out.println("=".repeat(40));
        System.out.println("Enter 'back' to return to main menu");
        
        while (true) {
            System.out.print("\nEnter command or URL to analyze: ");
            String input = scanner.nextLine().trim();
            
            if (input.equalsIgnoreCase("back")) {
                break;
            }
            
            // Input validation
            if (input.isEmpty()) {
                System.out.println("[ERROR] Please enter a command to analyze.");
                continue;
            }
            
            if (input.length() > 1000) {
                System.out.println("[ERROR] Command too long (maximum 1000 characters).");
                continue;
            }
            
                    
            // Sanitize input to prevent injection
            if (containsSuspiciousCharacters(input)) {
                System.out.println("[WARNING] Input contains potentially dangerous characters!");
                System.out.print("Continue analysis? (y/n): ");
                String confirm = scanner.nextLine().trim().toLowerCase();
                if (!confirm.equals("y") && !confirm.equals("yes")) {
                    continue;
                }
            }
            
            // Analyze the command
            System.out.println("\n[INFO] Analyzing command...");
            DetailedAnalysisResult result = analyzer.analyzeCommandDetailed(input);
            displayDetailedResult(input, result);
        }
    }
    
    private static boolean containsSuspiciousCharacters(String input) {
        String[] suspiciousPatterns = {"<script", "javascript:", "vbscript:", "<iframe", "eval(", "exec("};
        String lowerInput = input.toLowerCase();
        for (String pattern : suspiciousPatterns) {
            if (lowerInput.contains(pattern)) {
                return true;
            }
        }
        return false;
    }
    
    private static void displayDetailedResult(String command, DetailedAnalysisResult result) {
        String rawClassification = result.getLabel();
        String displayClassification = normalizeClassification(rawClassification).toUpperCase();
        String prefix = getClassificationPrefix(displayClassification);
        
        // Console Output
        System.out.println("\n" + "=".repeat(80));
        System.out.println(prefix + " DETAILED ANALYSIS RESULT");
        System.out.println("=".repeat(80));
        System.out.println("Command/URL: " + command);
        System.out.println("Classification: " + displayClassification);
        System.out.println("Risk Score: " + String.format("%.4f", result.getScore()) + "/1.0");
        System.out.println();
        System.out.println("DETAILED BREAKDOWN:");
        System.out.println("-".repeat(40));
        System.out.println("Response: " + result.getResponse());
        System.out.println("Lolbin Score (0.05): " + result.getLolbin());
        System.out.println("Content Score (0.4): " + result.getContent());
        System.out.println("Frequency Score (0.2): " + result.getFrequency());
        System.out.println("Source Score (0.1): " + result.getSource());
        System.out.println("Network Score (0.1): " + result.getNetwork());
        System.out.println("Behavioural Score (0.1): " + result.getBehavioural());
        System.out.println("History Score (0.05): " + result.getHistory());
        System.out.println();
        System.out.println("Timestamp: " + new Date());
        System.out.println("Analyzed by: " + currentUser.getUsername());
        System.out.println("=".repeat(80));
        
        // Show alerts (use display classification for user-facing alerts)
        showDetailedAlert(displayClassification, command, result);
        
        // Log to file (use original classification to preserve database accuracy)
        logger.info(String.format("DETAILED_ANALYSIS | User: %s | Command: %s | Classification: %s | DisplayedAs: %s | Score: %.4f | Lolbin: %s | Content: %s | Frequency: %s | Source: %s | Network: %s | Behavioural: %s | History: %s", 
                   currentUser.getUsername(), command, rawClassification, displayClassification, result.getScore(),
                   result.getLolbin(), result.getContent(), result.getFrequency(), 
                   result.getSource(), result.getNetwork(), result.getBehavioural(), result.getHistory()));
        
        System.out.println("\n[SUCCESS] Analysis complete. Detailed results logged to malcommandguard.log");
    }
    
    /**
     * Normalizes classification labels for consistent user display
     * Maps database variants to standard terminology
     */
    private static String normalizeClassification(String classification) {
        if (classification == null) return "legitimate";
        
        String normalized = classification.toLowerCase().trim();
        
        // Map database variants to standard display terms
        switch (normalized) {
            case "benign":
            case "legitimate":
            case "safe":
            case "clean":
                return "legitimate";
                
            case "malicious":
            case "malware":
            case "dangerous":
            case "harmful":
                return "malicious";
                
            case "suspicious":
            case "suspect":
            case "questionable":
            case "warning":
                return "suspicious";
                
            default:
                // For any unknown classification, default to legitimate
                return "legitimate";
        }
    }
    
    private static String getClassificationPrefix(String classification) {
        switch (classification.toLowerCase()) {
            case "malicious": return "[CRITICAL THREAT]";
            case "suspicious": return "[WARNING]";
            case "legitimate": return "[SAFE]";
            default: return "[SAFE]"; // Default to safe for unknown classifications
        }
    }
    
    private static void showDetailedAlert(String classification, String command, DetailedAnalysisResult result) {
        String alertMessage;
        String alertTitle;
        int messageType;
        
        switch (classification.toLowerCase()) {
            case "malicious":
                // Console Alert
                System.out.println("\n" + "!".repeat(80));
                System.out.println("CRITICAL SECURITY ALERT - MALICIOUS COMMAND DETECTED");
                System.out.println("!".repeat(80));
                System.out.println("DANGER: This command is classified as MALICIOUS!");
                System.out.println("ACTION: DO NOT EXECUTE - Report to security team immediately!");
                System.out.println("Risk Score: " + String.format("%.4f", result.getScore()));
                System.out.println("!".repeat(80));
                
                // GUI Popup Alert
                alertTitle = "CRITICAL SECURITY THREAT DETECTED";
                alertMessage = "MALICIOUS COMMAND DETECTED!\n\n" +
                             "Command: " + (command.length() > 50 ? command.substring(0, 50) + "..." : command) + "\n" +
                             "Risk Score: " + String.format("%.4f", result.getScore()) + "\n" +
                             "Classification: MALICIOUS\n\n" +
                             "WARNING: DO NOT EXECUTE THIS COMMAND!\n" +
                             "Contact your security team immediately!";
                messageType = JOptionPane.ERROR_MESSAGE;
                break;
                
            case "suspicious":
                // Console Alert
                System.out.println("\n" + "!".repeat(60));
                System.out.println("WARNING - SUSPICIOUS ACTIVITY DETECTED");
                System.out.println("!".repeat(60));
                System.out.println("CAUTION: This command requires investigation!");
                System.out.println("RECOMMENDATION: Manual review recommended before execution");
                System.out.println("Risk Score: " + String.format("%.4f", result.getScore()));
                System.out.println("!".repeat(60));
                
                // GUI Popup Alert
                alertTitle = "SUSPICIOUS ACTIVITY WARNING";
                alertMessage = "SUSPICIOUS COMMAND DETECTED!\n\n" +
                             "Command: " + (command.length() > 50 ? command.substring(0, 50) + "..." : command) + "\n" +
                             "Risk Score: " + String.format("%.4f", result.getScore()) + "\n" +
                             "Classification: SUSPICIOUS\n\n" +
                             "Recommendation: Manual investigation required\n" +
                             "Proceed with caution!";
                messageType = JOptionPane.WARNING_MESSAGE;
                break;
                
            case "legitimate":
            default:
                // Console Info
                System.out.println("\n[INFO] Command appears legitimate");
                System.out.println("[INFO] Low risk score: " + String.format("%.4f", result.getScore()));
                System.out.println("[INFO] Classification: LEGITIMATE - Proceed with normal caution");
                
                // GUI Info
                alertTitle = "Command Analysis Complete";
                alertMessage = "LEGITIMATE COMMAND\n\n" +
                             "Command: " + (command.length() > 50 ? command.substring(0, 50) + "..." : command) + "\n" +
                             "Risk Score: " + String.format("%.4f", result.getScore()) + "\n" +
                             "Classification: LEGITIMATE\n\n" +
                             "This command appears to be safe.";
                messageType = JOptionPane.INFORMATION_MESSAGE;
                break;
        }
        
        // Show GUI popup in separate thread to avoid blocking
        final String finalTitle = alertTitle;
        final String finalMessage = alertMessage;
        final int finalMessageType = messageType;
        
        Thread popupThread = new Thread(() -> {
            try {
                JOptionPane.showMessageDialog(null, finalMessage, finalTitle, finalMessageType);
            } catch (Exception e) {
                System.out.println("[WARNING] Could not display GUI popup: " + e.getMessage());
            }
        });
        popupThread.start();
    }
    
    private static void showStatistics() {
        System.out.println("\nSYSTEM STATISTICS & INFORMATION");
        System.out.println("=".repeat(50));
        
        Map<String, Integer> stats = analyzer.getClassificationStats();
        System.out.println("DATABASE STATISTICS:");
        System.out.println("Total Entries: " + analyzer.getDatabaseSize());
        System.out.println("Malicious: " + stats.getOrDefault("malicious", 0));
        System.out.println("Suspicious: " + stats.getOrDefault("suspicious", 0));
        System.out.println("Legitimate: " + stats.getOrDefault("legitimate", 0));
        
        System.out.println("Detection Rules Loaded: " + analyzer.getDetectionRulesCount());
                
        
        System.out.println("\nSYSTEM INFORMATION:");
        System.out.println("Java Version: " + System.getProperty("java.version"));
        System.out.println("Operating System: " + System.getProperty("os.name"));
        System.out.println("Current User: " + currentUser.getUsername() + " (" + currentUser.getRole() + ")");
        
        Runtime runtime = Runtime.getRuntime();
        long usedMemory = runtime.totalMemory() - runtime.freeMemory();
        System.out.println("Memory Usage: " + formatBytes(usedMemory) + " / " + formatBytes(runtime.totalMemory()));
        
        System.out.println("\nSECURITY FEATURES ACTIVE:");
        System.out.println("- Secure User Registration and authentication");
        System.out.println("- Login Attempt Limiting (Max 3 attempts)");
        System.out.println("- Password Hashing (SHA-256)");
        System.out.println("- Password Masking (GUI secure input dialogs)");
        System.out.println("- Input Validation & Sanitization");
        System.out.println("- Role-based Access Control");
        System.out.println("- Comprehensive Logging");
        System.out.println("- GUI Popup Alerts");
        System.out.println("- Console Output Alerts");
        System.out.println("- Secure file handling");
        System.out.println("- VirusTotal API Integration");
                
      
    }
    
    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        String pre = "KMGTPE".charAt(exp - 1) + "";
        return String.format("%.1f %sB", bytes / Math.pow(1024, exp), pre);
    }
    
    private static void adminMenu() {
        System.out.println("\nADMINISTRATOR PANEL");
        System.out.println("=".repeat(30));
        System.out.println("1. View All Users");
        System.out.println("2. Database Information");
        System.out.println("3. Show Log File Location");
        System.out.println("4. Back to Main Menu");
        System.out.print("Admin option: ");
        
        String choice = scanner.nextLine().trim();
        switch (choice) {
            case "1":
                userManager.displayAllUsers();
                break;
            case "2":
                analyzer.displayDatabaseInfo();
                break;
            case "3":
                showLogFileLocation();
                break;
            case "4":
                return;
            default:
                System.out.println("[ERROR] Invalid admin option.");
        }
    }
    
    private static void showLogFileLocation() {
        System.out.println("\nLOG FILE INFORMATION");
        System.out.println("=".repeat(30));
        
        File logFile = new File("malcommandguard.log");
        System.out.println("Log File Name: malcommandguard.log");
        System.out.println("Full Path: " + logFile.getAbsolutePath());
        System.out.println("File Exists: " + (logFile.exists() ? "Yes" : "No"));
        
        if (logFile.exists()) {
            System.out.println("File Size: " + formatBytes(logFile.length()));
            System.out.println("Last Modified: " + new Date(logFile.lastModified()));
            System.out.println("Readable: " + (logFile.canRead() ? "Yes" : "No"));
            System.out.println("Writable: " + (logFile.canWrite() ? "Yes" : "No"));
        }
        
        System.out.println("\nNOTE: This is always a single file (no .1, .2, etc. numbered files)");
        System.out.println("You can open it with any text editor like Notepad or NetBeans.");
    }
    
    
    private static void showHelp() {
        System.out.println("\nHELP & SYSTEM INFORMATION");
        System.out.println("=".repeat(60));
        System.out.println("PURPOSE:");
        System.out.println("   MalCommandGuard is an advanced security system that detects");
        System.out.println("   malicious commands and URLs using rule-based analysis with");
        System.out.println("   comprehensive database lookup and detailed scoring.");
        System.out.println("   This system also integrating VirusTotal API for wider use. ");
        System.out.println();
        System.out.println("DETECTION METHODS:");
        System.out.println("   - Excel database matching with detailed breakdown");
        System.out.println("   - Rule-based pattern recognition");
        System.out.println("   - Multi-factor risk scoring system");
        System.out.println("   - Lolbin, Content, Frequency, Source, Network, Behavioural, History analysis");
        System.out.println("   - VirusTotal API integration for cloud-based analysis");
        System.out.println();
        System.out.println("ALERT SYSTEMS:");
        System.out.println("   - Console output with detailed information");
        System.out.println("   - GUI popup notifications");
        System.out.println("   - Comprehensive log file recording");
        System.out.println("   - VirusTotal cloud analysis reports");
        System.out.println();
        System.out.println("SECURITY FEATURES:");
        System.out.println("   - Secure User Registration and authentication");
        System.out.println("   - Login Attempt Limiting (Max 3 attempts)");
        System.out.println("   - Password Hashing (SHA-256)");
        System.out.println("   - Password Masking (GUI secure input dialogs)");
        System.out.println("   - Input Validation & Sanitization");
        System.out.println("   - Role-based Access Control");
        System.out.println("   - Comprehensive Logging");
        System.out.println("   - GUI Popup Alerts");
        System.out.println("   - Console Output Alerts");
        System.out.println("   - Secure file handling");
        System.out.println("   - VirusTotal API Integration");
        System.out.println();
        System.out.println("INTEGRATE VIRUSTOTAL ANALYSIS:");
        System.out.println("   - URL scanning and reputation check");
        System.out.println("   - File hash analysis against malware database");
        System.out.println("   - Command pattern analysis with cloud intelligence");
        System.out.println();
        System.out.println("TEST COMMANDS:");
        System.out.println("   Malicious: certutil -urlcache, http://www.eicar.org/download/eicar.com.txt");
        System.out.println("   Suspicious: net user administrator, whoami /priv");
        System.out.println("   Legitimate: ipconfig /all, ping google.com");
        System.out.println();

       
    }
    
    // Static inner class for VirusTotal integration
    static class VirusTotalIntegration {
        private static final String VIRUSTOTAL_API_KEY = "34b3d55026757e05968cecdc3a11d5f8f10b32fc816a03911fab0cf784e2f5b1";
        private static final String VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/vtapi/v2/";
        
        private HttpClient httpClient;
        private ObjectMapper objectMapper;
        
        public VirusTotalIntegration() {
            this.httpClient = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(30))
                    .build();
            this.objectMapper = new ObjectMapper();
        }
        
        public void executeVirusTotalAnalysis(Scanner scanner) {
            System.out.println("\n=== VirusTotal Analysis ===");
            System.out.println("1. Analyze URL");
            System.out.println("2. Analyze File Hash");
            System.out.println("3. Analyze Command/String");
            System.out.println("4. Back to Main Menu");
            System.out.print("Select analysis type: ");
            
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline
            
            switch (choice) {
                case 1:
                    analyzeURL(scanner);
                    break;
                case 2:
                    analyzeFileHash(scanner);
                    break;
                case 3:
                    analyzeCommand(scanner);
                    break;
                case 4:
                    return;
                default:
                    System.out.println("Invalid choice!");
            }
        }
        
        private void analyzeURL(Scanner scanner) {
            System.out.print("Enter URL to analyze: ");
            String url = scanner.nextLine();
            
            try {
                String scanResult = submitURL(url);
                System.out.println("URL submitted for scanning...");
                Thread.sleep(2000);
                String report = getURLReport(url);
                displayURLReport(report);
            } catch (Exception e) {
                System.err.println("Error analyzing URL: " + e.getMessage());
            }
        }
        
        private String submitURL(String url) throws Exception {
            String requestBody = "apikey=" + VIRUSTOTAL_API_KEY + "&url=" + java.net.URLEncoder.encode(url, StandardCharsets.UTF_8);
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(VIRUSTOTAL_BASE_URL + "url/scan"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.body();
        }
        
        private String getURLReport(String url) throws Exception {
            String encodedUrl = java.net.URLEncoder.encode(url, StandardCharsets.UTF_8);
            String requestUrl = VIRUSTOTAL_BASE_URL + "url/report?apikey=" + VIRUSTOTAL_API_KEY + "&resource=" + encodedUrl;
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(requestUrl))
                    .GET()
                    .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.body();
        }
        
        private void displayURLReport(String jsonReport) {
            try {
                JsonNode root = objectMapper.readTree(jsonReport);
                
                System.out.println("\n=== URL Analysis Report ===");
                System.out.println("URL: " + root.get("url").asText());
                System.out.println("Scan Date: " + root.get("scan_date").asText());
                System.out.println("Positives: " + root.get("positives").asInt());
                System.out.println("Total Scans: " + root.get("total").asInt());
                
                if (root.get("positives").asInt() > 0) {
                    System.out.println(" WARNING: This URL is flagged as malicious!");
                    System.out.println("Permalink: " + root.get("permalink").asText());
                } else {
                    System.out.println("URL appears to be clean.");
                }
            } catch (Exception e) {
                System.err.println("Error parsing URL report: " + e.getMessage());
            }
        }
        
        private void analyzeFileHash(Scanner scanner) {
            System.out.print("Enter file hash (MD5, SHA1, or SHA256): ");
            String hash = scanner.nextLine();
            
            try {
                String report = getFileReport(hash);
                displayFileReport(report);
            } catch (Exception e) {
                System.err.println("Error analyzing file hash: " + e.getMessage());
            }
        }
        
        private String getFileReport(String hash) throws Exception {
            String requestUrl = VIRUSTOTAL_BASE_URL + "file/report?apikey=" + VIRUSTOTAL_API_KEY + "&resource=" + hash;
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(requestUrl))
                    .GET()
                    .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.body();
        }
        
        private void displayFileReport(String jsonReport) {
            try {
                JsonNode root = objectMapper.readTree(jsonReport);
                
                System.out.println("\n=== File Analysis Report ===");
                
                if (root.get("response_code").asInt() == 0) {
                    System.out.println("File not found in VirusTotal database.");
                    return;
                }
                
                System.out.println("File: " + root.get("resource").asText());
                System.out.println("Scan Date: " + root.get("scan_date").asText());
                System.out.println("Positives: " + root.get("positives").asInt());
                System.out.println("Total Scans: " + root.get("total").asInt());
                
                if (root.get("positives").asInt() > 0) {
                    System.out.println("WARNING: This file is flagged as malicious!");
                    System.out.println("Permalink: " + root.get("permalink").asText());
                } else {
                    System.out.println("File appears to be clean.");
                }
            } catch (Exception e) {
                System.err.println("Error parsing file report: " + e.getMessage());
            }
        }
        
        private void analyzeCommand(Scanner scanner) {
            System.out.print("Enter command or string to analyze: ");
            String command = scanner.nextLine();
            
            try {
                String hash = createSHA256Hash(command);
                System.out.println("Generated SHA256 hash: " + hash);
                String report = getFileReport(hash);
                displayFileReport(report);

            } catch (Exception e) {
                System.err.println("Error analyzing command: " + e.getMessage());
            }
        }
        
        private String createSHA256Hash(String input) throws Exception {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        }
        


        
    }
}