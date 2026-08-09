# Sensitive File Scanner

## Description
A command-line tool that scans a **local folder** for potentially sensitive files that may contain private or important information. It checks files based on their extensions and filename keywords, such as `.env` files, database backups, configuration files, and other sensitive files.

The tool also shows why each file was flagged, whether it was detected because of its file extension or its filename, along with a severity rating.

## Purpose
yada yada

## Features
- **Extension check**: flags files whose extension matches an entry in `wordlists/extensions_list.txt` (~2,400 entries).
- **Filename keyword check**: flags files whose name contains a known sensitive keyword from `wordlists sensitive_filenames.txt` (e.g. `.env`, `.git`, `id_rsa`, `web.config`), even if the extension is not included in the extensions wordlist.
- **Severity scoring**: each finding is rated CRITICAL, HIGH, MEDIUM, or LOW based on how sensitive its filename/extension typically is (e.g. private keys are CRITICAL, config files are MEDIUM). Results are sorted by severity, most critical first.
- **Curated extensions list**: an optional, trimmed extensions wordlist (`wordlists/extensions_curated_list.txt`)
-  **Custom wordlists**: you can point the scanner to your own wordlist files. 
- **Labeled findings**: each result shows why it was flagged, either `Sensitive extension` or `Sensitive filename`, so it is clear which rule detected it.
- **Inline extension list**: pass extensions directly on the command line without needing a wordlist file at all.
- **Case-insensitive matching**: extension and filename checks are not case-sensitive, so `CONFIG.PHP` and `config.php` are both caught.
- **CSV export**: save scan results to a CSV file (saved in the `results/` folder, created automatically if it does not exist), including severity breakdown counts.
- **Formatted results summary**: displays files scanned, total findings, a breakdown between sensitive extensions and filenames, a severity breakdown, scan duration, and a list of the flagged files.

## System Requirements
- Python 3.8+
- Windows, Linux or macOS

## Installation
1. Clone or download this repository.
2. Ensure Python 3.8+ is installed.

| Windows     | py --version      |
|-------------|-------------------|
| Linux/macOS | python3 --version |

3. Open a terminal and navigate to the tool's root folder:
    - cd path/to/NSSECU2_HACKING-TOOL
4. No additional Python packages are required. The tool only uses Python's built-in libraries.

### Windows
Run the tool using Python:
    python filebuster.py --help

You can also use the included batch file:
    filebuster.bat --help

### Linux/macOS
make the shell script executable:
    chmod +x filebuster.sh

Run the tool using Python:
    python3 filebuster.py --help

Or use the included shell script:
    ./filebuster.sh --help

## Usage
Run from inside the tool's root folder (required, since wordlist paths are relative to it):

```bash
python scanner.py --path [TARGET_DIRECTORY]
```

### Options

| Options | Description |
|---|---|
| `--path` | Directory to scan (default: current working directory) |
| `--ext` | Comma-separated list of extensions to scan for, e.g. `--ext .env,.key,.pem` (overrides all extension wordlists) |
| `--cur` | Use the shorter curated extensions wordlist instead of the full list |
| `--ce` | Path to a custom extensions wordlist file |
| `--cf` | Path to a custom sensitive filenames wordlist file |
| `--csv` | Save results to a CSV file inside the `results/` folder, e.g. `--csv scan1.csv` |

### Examples

Scan a folder with the default (full) extensions list:
```bash
python scanner.py --path "[file_path]"
```

Scan using the shorter curated extensions list:
```bash
python scanner.py --path "[file_path]" --cur
```

Scan for specific extensions only:
```bash
python scanner.py --path "[file_path]" --ext .env,.key,.pem
```

Use your own custom wordlists:
```bash
python scanner.py --path "[file_path]" --ce my_ext.txt --cf my_keywords.txt
```

Export results to CSV:
```bash
python scanner.py --path "[file_path]" --cur --csv scan_results.csv
```

## Testing Environment
This tool was tested against:

yada yada

## Sample Output
yada yada

## Limitations
yada yada

## Future Improvements
yada yada

## Ethical Disclaimer
This tool was developed for educational purposes only. It must only be used in authorized and controlled testing environments. Unauthorized testing against real systems, public websites, or third-party services is strictly prohibited.


## Group Members and Roles
| Name | Role                               |
|---|------------------------------------|
| Bendol, Trisha | *Developer*                        |
| Camato, Karl | *Developer*                        |
| Chua, Myka | *Developer*                        |
| Lim, Julienne | *Developer, Presentation Designer* |
| Obregon, Sian | *Developer*                        |

## Original Contribution
Each group must clearly state what they personally built and what makes the tool unique.

Example:

Our original contribution is the custom scoring engine and recommendation system that evaluates login security based on failed attempts, response messages, lockout behavior, and rate limiting.

## References

Wordlists:
- [Extensions List](https://github.com/TrustMe00/senstives-files)
- [Filename List](https://github.com/emadshanab/WordLists-20111129)
- [CSV files in Python](https://www.geeksforgeeks.org/python/writing-csv-files-in-python/)
