# Sensitive File Scanner

## Features [not required]
TODO:
- add shorter extension list option
- add option for user to put unique wordlist path
- add option for csv
FINISHED:
- sensitive filenames
- sensitive extensions
- specific extensions option
- error handling for path dne

## Description
A command-line tool that scans a **local folder** for potentially sensitive files that may contain private or important information. It checks files based on their extensions and filename keywords, such as `.env` files, database backups, configuration files, and other sensitive files.

The tool also shows why each file was flagged, whether it was detected because of its file extension or its filename.

## Purpose
yada yada

## Features
- **Extension check**: flags files whose extension matches an entry in `wordlists/extensions_list.txt` (~2,400 entries).
- **Filename keyword check**: flags files whose name contains a known sensitive keyword from `wordlists sensitive_filenames.txt` (e.g. `.env`, `.git`, `id_rsa`, `web.config`), even if the extension is not included in the extensions wordlist.
- **Curated extensions list**: an optional, trimmed extensions wordlist (`wordlists/extensions_curated_list.txt`)
-  **Custom wordlists**: you can point the scanner to your own wordlist files. 
- **Labeled findings**: each result shows why it was flagged, either `Sensitive extension` or `Sensitive filename`, so it is clear which rule detected it.
- **Inline extension list**: pass extensions directly on the command line without needing a wordlist file at all.
- **CSV export**: save scan results to a CSV file (saved in the `results/` folder) 
- **Formatted results summary**: displays the total number of findings, a breakdown between sensitive extensions and filenames, and a list of the flagged files.

## System Requirements
- Python 3.8+

## Installation
yada yada

## Usage
yada yada

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
| Name | Role |
|---|---|
| Bendol, Trisha | *(yada yada)* |
| Camato, Karl | *(yada yada)* |
| Chua, Myka | *(yada yada)* |
| Lim, Julienne | *(yada yada)* |
| Obregon, Sian | *(yada yada)* |

## Original Contribution
Each group must clearly state what they personally built and what makes the tool unique.

Example:

Our original contribution is the custom scoring engine and recommendation system that evaluates login security based on failed attempts, response messages, lockout behavior, and rate limiting.


## References

Wordlists:
- [Extensions List](https://gist.github.com/securifera/e7eed730cbe1ce43d0c29d7cd2d582f4)
- [Filename List](https://github.com/emadshanab/WordLists-20111129)
- [CSV files in Python](https://www.geeksforgeeks.org/python/writing-csv-files-in-python/)
