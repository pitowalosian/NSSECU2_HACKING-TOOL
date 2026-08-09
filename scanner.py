import os, sys
from os import walk
from os.path import isfile, join, exists
import argparse

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
            wordlist.append(stripped)

    return wordlist

def is_sensitive(filename, ext_list):
    """Return True if filename has a sensitive extension."""

    name_lower = filename.lower()

    for ext in ext_list:
        if name_lower.endswith(ext):
            return True

    return False
 
def is_sensitive_filename(filename, sensitive_list):
    """Return true if filename contains a sensitive keyword."""

    name_lower = filename.lower()

    for sensitive in sensitive_list:
        if sensitive in name_lower:
            return True

    return False
        
def scan(path, ext_list, filename_list):
    
    sensitive_files = []

    for (dirpath, dirnames, filenames) in walk(path):
        for f in filenames:
            fullpath = join(dirpath, f)
            if is_sensitive(f, ext_list):
                sensitive_files.append((fullpath, "Sensitive extension"))

            elif is_sensitive_filename(f, filename_list):
                sensitive_files.append((fullpath, "Sensitive filename"))

    return sensitive_files

def display_results(path, findings):
    # For findings
    extension_count = 0
    filename_count = 0

    for file, reason in findings:
        if reason == "Sensitive extension":
            extension_count += 1
        elif reason == "Sensitive filename":
            filename_count += 1

    # Results
    print("=====================================================================")
    print("                              SCAN RESULTS")
    print("=====================================================================")

    print(f"\nTarget:")
    print(f"{path}")

    print(f"\nTotal findings: {len(findings)}")
    print(f"Sensitive extensions: {extension_count}")
    print(f"Sensitive filenames: {filename_count}")

    print("\n=====================================================================")
    print("SENSITIVE FILES")
    print("=====================================================================")

    if findings:
        for i, (file, reason) in enumerate(findings, start=1):
            filename = os.path.basename(file)

            print(f"\n[{i}] {reason}")
            print(f"    File: {filename}")
            print(f"    Path: {file}")
    else:
        print("\nNo sensitive files found.")

    print("\n" + "=====================================================================")
    print("                      ~~!SCAN COMPLETE!~~")
    print("=====================================================================")

if __name__ == "__main__":
    # to run: python scanner.py --path [insert path]
    banner()
    parser = argparse.ArgumentParser(description='Choose directory to scan', usage='%(prog)s --path [PATH]')
    parser.add_argument('--path',
                      default=os.getcwd(),
                      help='directory to scan (default: current directory)') # default scan current directory
    parser.add_argument('--ext',
                        type=lambda s: s.split(','),
                        default=None,
                        help='file extensions to scan, e.g. --ext .env,.key,.pem')
    
    args = parser.parse_args()

    # Error handling
    if not exists(args.path):
        sys.exit(f"Error: Path {args.path} not found")
        
    
    print(f"Scanning {args.path} for sensitive files.\n\n")

    # Loading the wordlists
    if (args.ext):
        ext_list = args.ext
    else:
        ext_list = load_wordlist("wordlists/extensions_list.txt")

    filename_list = load_wordlist("wordlists/sensitive_filenames.txt")

    # Scanning
    findings = scan(args.path, ext_list, filename_list)

    # Display the results
    display_results(args.path, findings)
