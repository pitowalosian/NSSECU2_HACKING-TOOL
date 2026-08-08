import os
from os import walk
from os.path import isfile, join
import argparse

def scan(path):
    
    f = []

    for (dirpath, dirnames, filenames) in walk(path):
        f.extend(filenames)
        break

if __name__ == "__main__":
    # to run: python scanner.py --path [insert path]
    parser = argparse.ArgumentParser(description='Choose directory to scan')
    parser.add_argument('--path',
                      default=os.getcwd()) # default scan current directory
    
    args = parser.parse_args()

    print(f"Scanning {args.path} for sensitive files.")

    f = scan(args.path)