import os, sys
from os import walk
from os.path import join, exists
import argparse
import csv
import time

def banner():
    print("""
        ███████╗██╗██╗     ███████╗██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ 
        ██╔════╝██║██║     ██╔════╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
        █████╗  ██║██║     █████╗  ██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
        ██╔══╝  ██║██║     ██╔══╝  ██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
        ██║     ██║███████╗███████╗██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
        ╚═╝     ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    """)

    print("Made by: Bendol, Camato, Chua, Lim, Obregon\n\n")

def load_wordlist(filepath):
    """Read extensions from a file, one per line."""
    with open(filepath, 'r') as f:
        wordlist = []

        for line in f:
            stripped = line.strip()
            if stripped:
                wordlist.append(stripped.lower())

        return wordlist

def is_sensitive(filename, ext_list):
    """Return a list of matched sensitive extensions."""
    name_lower = filename.lower()
    matches = []
    for ext in ext_list:
        ext = ext.strip().lower()
        if not ext.startswith('.'):
            ext = '.' + ext
        if name_lower.endswith(ext):
            matches.append(("Sensitive extension", ext))
    return matches

def is_sensitive_filename(filename, filename_list):
    """Return a list of matched sensitive keywords."""
    name_lower = filename.lower()
    matches = []
    for keyword in filename_list:
        keyword = keyword.strip().lower()
        if keyword.startswith('.'):
            continue
        if keyword.lower() == name_lower:
            matches.append(("Sensitive filename", keyword))
            
    return matches

def get_severity(filename):
    """
    Determine the potential severity of a finding based on its filename/extension.

    Severity priority:
    CRITICAL --> HIGH --> MEDIUM --> LOW
    """

    name_lower = filename.lower()

    # CRITICAL: Private keys/authentication-related secrets
    critical_terms = [
        # Private key extensions
        ".key",
        ".pem",
        ".pfx",
        ".p12",
        ".ppk",

        # Private key filenames
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "private_key",
        "authorized_keys",

        # Authentication secrets
        "api_key",
        "apikey",
        "secret",
        "token"
    ]

    # HIGH: Credentials, databases/backups
    high_terms = [
        # Credential-related files
        ".env",
        ".psw",
        ".pwd",
        ".pgpass",
        ".netrc",
        "password",
        "passwd",
        "credential",
        "creds",

        # Database files
        ".sql",
        ".sqlite",
        ".sqlite3",
        ".db",
        ".mdb",
        ".accdb",

        # Database backups / dumps
        ".bak",
        ".dump",
        ".dmp",
        "database",
        "backup"
    ]

    # MEDIUM: Configuration and potentially sensitive data files
    medium_terms = [
        # Configuration files
        ".config",
        ".ini",
        ".conf",
        ".cfg",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".toml",
        ".properties",

        # Server/security configuration
        ".htpasswd",
        ".htaccess",

        # Potentially sensitive data/log files
        ".csv",
        ".log"
    ]

    # LOW: Files that could have useful/sensitive information, but generally less indicative of exposed secrets
    low_terms = [
        ".pdf",
        ".xls",
        ".xlsx",
        ".doc",
        ".docx",
        ".txt",
        ".zip",
        ".rar",
        ".tar",
        ".7z",
        ".gz",
    ]

    # To check each severity category

    for term in critical_terms:
        if term in name_lower:
            return "CRITICAL"

    for term in high_terms:
        if term in name_lower:
            return "HIGH"

    for term in medium_terms:
        if term in name_lower:
            return "MEDIUM"

    for term in low_terms:
        if term in name_lower:
            return "LOW"

    # Default severity for files that don't match any of the predefined severity terms
    return "LOW"

def scan(path, ext_list, filename_list):
    """
    Scan directory for files with sensitive extensions or filenames

    Returns findings (list of detected files) and files_scanned (total number of files examined)
    """
    
    sensitive_files = []
    files_scanned = 0

    for (dirpath, dirnames, filenames) in walk(path):
        for f in filenames:
            fullpath = join(dirpath, f)
            files_scanned += 1

            reasons = []
            reasons.extend(is_sensitive(f, ext_list))
            reasons.extend(is_sensitive_filename(f, filename_list))

            if reasons:
                severity = get_severity(f)
                sensitive_files.append((fullpath, reasons, severity))

    # To order output based on severity
    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3
    }

    sensitive_files.sort (
        key = lambda item: (
            severity_order[item[2]], item[0].lower()
        )
    )

    return sensitive_files, files_scanned

def display_results(path, findings, files_scanned, scan_duration):
    # For findings
    extension_count = 0
    filename_count = 0

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for file, reasons, severity in findings:
        if any(cat == "Sensitive extension" for cat, _ in reasons):
            extension_count += 1
        if any(cat == "Sensitive filename" for cat, _ in reasons):
            filename_count += 1

        if severity == "CRITICAL":
            critical_count += 1
        elif severity == "HIGH":
            high_count += 1
        elif severity == "MEDIUM":
            medium_count += 1
        elif severity == "LOW":
            low_count += 1

    # Results (with statistics)
    print("=====================================================================")
    print("                            SCAN RESULTS")
    print("=====================================================================")

    print(f"\nTarget:")
    print(f"{path}")

    print(f"\nFiles scanned: {files_scanned}")
    print(f"\nTotal findings: {len(findings)}")

    print("\nDetection methods:")
    print(f"Sensitive extensions: {extension_count}")
    print(f"Sensitive filenames: {filename_count}")

    print("\nPotential severity:")
    print(f"CRITICAL: {critical_count}")
    print(f"HIGH:     {high_count}")
    print(f"MEDIUM:   {medium_count}")
    print(f"LOW:      {low_count}")

    print(f"\nScan duration: {scan_duration:.4f} seconds")


    print("\n=====================================================================")
    print("                           DETECTED FILES")
    print("=====================================================================")

    if findings:
        for i, (file, reasons, severity) in enumerate(findings, start=1):
            filename = os.path.basename(file)

            print(f"\n[{i}] {severity}")
            print(f"    File: {filename}")
            print(f"    Path: {file}")
            for cat, detail in reasons:
                print(f"    Reason: {cat} ({detail})")
    else:
        print("\nNo sensitive files found.")

    print("\n=====================================================================")
    print("                        ~~! SCAN COMPLETE !~~")
    print("=====================================================================")


def save_csv(findings, output_path):
    """Store findings in a CSV file"""
    extension_count = 0
    filename_count = 0

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for file, reason, severity in findings:
        if any(cat == "Sensitive extension" for cat, _ in reasons):
            extension_count += 1
        if any(cat == "Sensitive filename" for cat, _ in reasons):
            filename_count += 1

        if severity == "CRITICAL":
            critical_count += 1
        elif severity == "HIGH":
            high_count += 1
        elif severity == "MEDIUM":
            medium_count += 1
        elif severity == "LOW":
            low_count += 1

    # To create directory automatically if it doesn't exist yet
    os.makedirs(os.path.dirname(output_path), exist_ok = True)

    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Total findings", len(findings)])
        writer.writerow(["Sensitive extensions", extension_count])
        writer.writerow(["Sensitive filenames", filename_count])

        writer.writerow(["Critical findings", critical_count])
        writer.writerow(["High findings", high_count])
        writer.writerow(["Medium findings", medium_count])
        writer.writerow(["Low findings", low_count])
        writer.writerow([])

        writer.writerow(["File", "Path", "Reason", "Severity"])
        for file, reasons, severity in findings:
           reason_text = "; ".join(f"{cat} ({detail})" for cat, detail in reasons)
        writer.writerow( os.path.basename(file), file, reason_text, severity)

    print(f"\nResults saved to {output_path}")

if __name__ == "__main__":
    # to run: python scanner.py --path [insert path]
    banner()
    parser = argparse.ArgumentParser(description='Choose directory to scan', usage='%(prog)s --path [PATH]')
    parser.add_argument('--path',
                        default=os.getcwd(),
                        metavar='[TARGET_DIR]',
                        help='directory to scan (default: current directory)')
    parser.add_argument('--ext',
                        type=lambda s: s.split(','),
                        default=None,
                        metavar='[SPECIFIC_EXT]',
                        help='file extensions to scan, e.g. --ext .env,.key,.pem')
    parser.add_argument('--ce',
                        default=None,
                        metavar='[EXT_FILE]',
                        help='path to a custom extensions wordlist file, e.g. --ce my_ext.txt')
    parser.add_argument('--cf',
                        default=None,
                        metavar='[KEYWORDS_FILE]',
                        help='path to a custom sensitive filenames wordlist file,  e.g. --cf my_keywords.txt')
    parser.add_argument('--csv',
                        default=None,
                        metavar='[OUTPUT.csv]',
                        help='save results to a CSV file, e.g. --csv results.csv')

    args = parser.parse_args()

    # Error handling
    if not exists(args.path):
        sys.exit(f"Error: Path {args.path} not found")

    if args.ce and not exists(args.ce):
        sys.exit(f"Error: Extensions wordlist {args.ce} not found")

    if args.cf and not exists(args.cf):
        sys.exit(f"Error: Filenames wordlist {args.cf} not found")


    print(f"Scanning {args.path} for sensitive files.\n\n")

    # Loading the wordlists
    if args.ext:
        ext_list = args.ext
    elif args.ce:
        ext_list = load_wordlist(args.ce)
    else:
        ext_list = load_wordlist("wordlists/extensions_list.txt")

    if args.cf:
        filename_list = load_wordlist(args.cf)
    else:
        filename_list = load_wordlist("wordlists/filenames.txt")

    # Start scan timer
    start_time = time.perf_counter()

    # Scanning
    findings, files_scanned = scan(args.path, ext_list, filename_list)

    # Stop scan timer
    end_time = time.perf_counter()
    scan_duration = end_time - start_time

    # Display the results
    display_results(args.path, findings, files_scanned, scan_duration)

    # Save results to CSV
    if args.csv:
        output_path = join("results", args.csv)
        save_csv(findings, output_path)
