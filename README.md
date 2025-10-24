# Existing Tickets Triage Automation

This project automates the triage of security findings from Excel files, integrating with Checkmarx and JIRA APIs. It processes Excel files in a specified folder, updates findings in Checkmarx, and summarizes the results.

---

## How to Run the Script

You can run the main script from the command line:

```bash
python3 existing_tickets_triage.py -date YYYYMMDD [--sheet_name SHEET] [--excel_file FILENAME]
```

### Arguments

| Argument         | Required | Description                                                                                  |
|------------------|----------|----------------------------------------------------------------------------------------------|
| `-date` / `--date`        | No       | Date-named subfolder inside `jira_tickets` (e.g., `20251021`). If not provided, uses today's date. |
| `-sheet` / `--sheet_name` | No       | Optional sheet name (default: first sheet).                                                   |
| `--excel_file`            | No       | Optional Excel file to process (e.g., `ticket.xlsx`). If not provided, processes all files in the folder. |

> **Note:** The script always reads from column 'B' in the Excel files.

---

## Script Logical Flow

1. **Argument Parsing**: Parses command-line arguments for date, sheet name, and Excel file.
2. **Folder and File Selection**: Determines the target folder (`jira_tickets/{date}`) and Excel files to process.
3. **Processing Each Excel File**:
    - Reads JIRA ticket ID, DevSecOps type, and report URL from the Excel file.
    - Extracts project and scan IDs from the report URL.
    - Verifies scan ID via Checkmarx API.
    - Depending on the DevSecOps type (`SAST`, `SCA`, `CSEC`), processes the file accordingly:
        - Reads relevant cells for vulnerability/package/CVE data.
        - Maps triage status to Checkmarx state/severity.
        - Updates findings in Checkmarx via API.
    - Logs results and accumulates a summary for each file.
4. **Summary Generation**: After processing, writes a markdown summary table (`triage_run_summary.md`) with Excel file, JIRA ticket, DevSecOps type, and status.
5. **GitHub Actions Integration**: The workflow appends the summary to the GitHub Actions run summary.

---

## File Structure

```
existing-tickets-triage-automation/
├── existing_tickets_triage.py
├── README.md
├── .github/
│   └── workflows/
│       └── appsec_triage_update_workflow.yml
├── checkmarx_utility/
│   ├── cx_api_actions.py
│   ├── cx_api_endpoints.py
│   ├── cx_config_utility.py
│   ├── cx_token_manager.py
│   └── .env_sample
├── utils/
│   ├── excel_reader.py
│   ├── exception_handler.py
│   ├── helper_functions.py
│   ├── http_utility.py
│   ├── json_file_utility.py
│   ├── logger.py
│   └── yml_file_utility.py
├── logs/
├── .gitignore
```

### File/Directory Descriptions

- **existing_tickets_triage.py**: Main script for processing Excel files, updating Checkmarx findings, and generating summaries.
- **README.md**: Project documentation and usage instructions.
- **.github/workflows/appsec_triage_update_workflow.yml**: GitHub Actions workflow for automating triage runs and publishing summaries.
- **checkmarx_utility/**: Contains modules for interacting with Checkmarx APIs and managing authentication.
    - `cx_api_actions.py`: Functions for Checkmarx API actions (scan details, predicates, etc.).
    - `cx_api_endpoints.py`: API endpoint definitions for Checkmarx.
    - `cx_config_utility.py`: Utility for Checkmarx configuration.
    - `cx_token_manager.py`: Handles Checkmarx API authentication tokens.
    - `.env_sample`: Sample environment variable file for Checkmarx credentials.
- **utils/**: Utility modules for Excel reading, logging, HTTP requests, and file handling.
    - `excel_reader.py`: Reads data from Excel files.
    - `exception_handler.py`: Custom exception handling utilities.
    - `helper_functions.py`: Helper functions for data extraction and formatting.
    - `http_utility.py`: HTTP request utilities.
    - `json_file_utility.py`: JSON file read/write utilities.
    - `logger.py`: Logging utility for console and file logs.
    - `yml_file_utility.py`: YAML file read/write utilities.
- **logs/**: Directory for log files generated during script execution.
- **.gitignore**: Specifies files and directories to be ignored by git.

---

## Example

Process all Excel files in today's folder:
```bash
python3 existing_tickets_triage.py
```

Process a specific file in a specific folder:
```bash
python3 existing_tickets_triage.py -date 20251021 --excel_file ticket.xlsx
```

---

## Notes

- Ensure all required environment variables and API credentials are set (see `.env_sample`).
- The script is designed to be run both locally and via GitHub Actions.
- The summary of each run is available in `triage_run_summary.md` and in the GitHub Actions run summary.
