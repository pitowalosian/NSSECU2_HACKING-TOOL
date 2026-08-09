# Sensitive File Scanner

## Description
A command-line tool that scans a **local folder** for potentially sensitive files that may contain private or important information. It checks files based on their extensions and filename keywords, such as `.env` files, database backups, configuration files, and other sensitive files.

The tool also shows why each file was flagged, whether it was detected because of its file extension or its filename, along with a severity rating.

## Purpose
yada yada

## User Manual
See the full user manual here  [User Manual]()

## Features
- **Extension check**: flags files whose extension matches an entry in `wordlists/extensions_list.txt` (a curated list of genuinely sensitive extensions, not a broad web-fuzzing wordlist).
- **Filename keyword check**: flags files whose name contains a known sensitive keyword from `wordlists/filenames.txt` (e.g. `.env`, `.git`, `id_rsa`, `web.config`), even if the extension is not included in the extensions wordlist.
- **Severity scoring**: each finding is rated CRITICAL, HIGH, MEDIUM, or LOW based on how sensitive its filename/extension typically is (e.g. private keys are CRITICAL, config files are MEDIUM). Results are sorted by severity, most critical first.
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
```bash
python casefiler.py --help
```

> **Note:** if `python` is not recognized or fails to run, your PATH may not be configured correctly. You'll need to fix it manually (e.g. via "Edit environment variables for your account" in Windows Settings), or use the `py` launcher instead (`py casefiler.py --help`).

You can also use the included batch file:
```bash
casefiler --help
```

### Linux/macOS
make the shell script executable:
```bash
chmod +x casefiler.sh
```

Run the tool using Python:
```bash
python casefiler.py --help
```

Or use the included shell script:
```bash
./casefiler.sh --help
```

## Usage
Run from inside the tool's root folder (required, since wordlist paths are relative to it):

```bash
python casefiler.py --path [TARGET_DIRECTORY]
```
```bash
 casefiler --path [TARGET_DIRECTORY]
```


### Options

| Options | Description |
|---|---|
| `--path` | Directory to scan (default: current working directory) |
| `--ext` | Comma-separated list of extensions to scan for, e.g. `--ext .env,.key,.pem` (overrides all extension wordlists) |
| `--ce` | Path to a custom extensions wordlist file |
| `--cf` | Path to a custom sensitive filenames wordlist file |
| `--csv` | Save results to a CSV file inside the `results/` folder, e.g. `--csv scan1.csv` |

### Examples

Scan a folder with the default extensions list:
```bash
 casefiler --path "[file_path]"
```

Scan for specific extensions only:
```bash
 casefiler --path "[file_path]" --ext .env,.key,.pem
```

Use your own custom wordlists:
```bash
 casefiler --path "[file_path]" --ce my_ext.txt --cf my_keywords.txt
```

Export results to CSV:
```bash
  casefiler --path "[file_path]" --csv scan_results.csv
```

## Testing Environment
This tool was tested against:

yada yada

## Sample Output
yada yada

## Limitations
Filebuster only scans file names and extensions and does not scan file contents. Files containing sensitive data may still be flagged as non-sensitive and vice versa. Additionally, severity ratings are hardcoded into the program. Severity ratings should only be used to get an initial idea of the files, and should not be taken as objective fact. Using a different wordlist could show missing severity ratings. 


## Future Improvements
yada yada

## Ethical Disclaimer
This tool was developed strictly for educational purposes as part of an academic course project. It is intended to help users understand how sensitive files can be identified through filename and extension analysis, within controlled and authorized environments only.

Additionally, this tool must only be used on systems, folders, or devices that you own or have documented authorization to scan. Unauthorized use against real systems, public websites, third-party services, or any environment without clear permission is strictly prohibited and may violate laws. The developers of this tool accept no responsibility for misuse. 


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
