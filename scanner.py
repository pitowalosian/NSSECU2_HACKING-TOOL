import os
from os import walk
from os.path import isfile, join
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

def is_sensitive(filename):
    """Return true if filename is part of wordlist"""

    name_lower = filename.lower()
    ext_list = load_wordlist("wordlists/extensions_list.txt")

    for ext in ext_list:
        if name_lower.endswith(ext):
            return True

    # TODO I think we can also scan sensitive filenames?

def scan(path):
    
    sensitive_files = []

    for (dirpath, dirnames, filenames) in walk(path):
        for f in filenames:
            fullpath = join(dirpath, f)
            if isfile(fullpath) and is_sensitive(f):
                sensitive_files.append(fullpath)

    return sensitive_files


if __name__ == "__main__":
    # to run: python scanner.py --path [insert path]
    banner()
    parser = argparse.ArgumentParser(description='Choose directory to scan')
    parser.add_argument('--path',
                      default=os.getcwd()) # default scan current directory
    
    args = parser.parse_args()

    print(f"Scanning {args.path} for sensitive files.\n\n")

    f = scan(args.path)

    if f:
        print(f"Found {len(f)} potentially sensitive files: \n")

    for file in f:
        print(f" - {file}")
    else:
        print("No sensitive files found.")