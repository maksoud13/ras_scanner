package com.maksoud.filescanner.modules.ransomware;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class RansomwarePatterns {

    // Known ransomware file extensions
    public static final List<String> RANSOMWARE_EXTENSIONS = Arrays.asList(
            ".locky", ".crypt", ".crypto", ".encrypted", ".ransom",
            ".blackmail", ".zepto", ".cerber", ".cry", ".r5a", ".xbt",
            ".kkk", ".xyz", ".zzz", ".aes", ".gpg", ".lukitus",
            ".crinf", ".rnsmwr", ".cryptolocker", ".payms", ".payrms",
            ".vector", ".sage", ".magic", ".serpent", ".odin",
            ".cryptowall", ".reveton", ".ctbl", ".encoded", ".locked",
            ".cryptolocker", ".coverton", ".efdc", ".exx", ".cryp1",
            ".crypz", ".rrk", ".enciphered", ".venusf", ".wflx",
            ".lockbit", ".conti", ".revil", ".maze", ".ryuk");

    // Ransomware-specific patterns in file content
    public static final List<Pattern> RANSOMWARE_CONTENT_PATTERNS = Arrays.asList(
            Pattern.compile("your files have been encrypted", Pattern.CASE_INSENSITIVE),
            Pattern.compile("pay the ransom", Pattern.CASE_INSENSITIVE),
            Pattern.compile("bitcoin.*address", Pattern.CASE_INSENSITIVE),
            Pattern.compile("decryption service", Pattern.CASE_INSENSITIVE),
            Pattern.compile("recover your files", Pattern.CASE_INSENSITIVE),
            Pattern.compile("personal id.*key", Pattern.CASE_INSENSITIVE),
            Pattern.compile("send.*money", Pattern.CASE_INSENSITIVE),
            Pattern.compile("cryptolocker", Pattern.CASE_INSENSITIVE),
            Pattern.compile("wannacry", Pattern.CASE_INSENSITIVE),
            Pattern.compile("notpetya", Pattern.CASE_INSENSITIVE),
            Pattern.compile("locky", Pattern.CASE_INSENSITIVE),
            Pattern.compile("cerber", Pattern.CASE_INSENSITIVE),
            Pattern.compile("teslacrypt", Pattern.CASE_INSENSITIVE));

    // Ransomware behavioral patterns (file operations)
    public static final List<Pattern> RANSOMWARE_BEHAVIOR_PATTERNS = Arrays.asList(
            Pattern.compile("vssadmin.*delete.*shadows", Pattern.CASE_INSENSITIVE),
            Pattern.compile("bcdedit.*/set.*recoveryenabled.*no", Pattern.CASE_INSENSITIVE),
            Pattern.compile("wbadmin.*delete.*catalog", Pattern.CASE_INSENSITIVE),
            Pattern.compile("remove-item.*-force", Pattern.CASE_INSENSITIVE),
            Pattern.compile("cipher.*/w", Pattern.CASE_INSENSITIVE),
            Pattern.compile("fsutil.*usn.*deletejournal", Pattern.CASE_INSENSITIVE),
            Pattern.compile("mountvol.*/d", Pattern.CASE_INSENSITIVE),
            Pattern.compile("wevtutil.*clear-log", Pattern.CASE_INSENSITIVE),
            Pattern.compile(
                    "reg.*delete.*HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("schtasks.*/delete", Pattern.CASE_INSENSITIVE));

    // Known ransomware process names
    public static final List<String> RANSOMWARE_PROCESS_NAMES = Arrays.asList(
            "wannacry.exe", "petya.exe", "notpetya.exe", "locky.exe",
            "cerber.exe", "cryptolocker.exe", "teslacrypt.exe",
            "reveton.exe", "cryptowall.exe", "badrabbit.exe",
            "gandcrab.exe", "ryuk.exe", "maze.exe", "conti.exe");

    // Ransomware network indicators
    public static final List<String> RANSOMWARE_DOMAINS = Arrays.asList(
            "onion", "tor2web", "bitcoin", "blockchain",
            "localbitcoins", "coinbase", "binance");
}
