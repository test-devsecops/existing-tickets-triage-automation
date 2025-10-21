import os
import sys
import argparse
from utils.excel_reader import ExcelReader
from utils.logger import Logger
from utils.helper_functions import HelperFunctions
from checkmarx_utility.cx_api_actions import CxApiActions
from checkmarx_utility.cx_token_manager import AccessTokenManager

def _get_cx_state_severity_score(triage_values_mapping, triage_status):
    """
    For CSEC only: returns (state, severity, score) where score is the string from the mapping (not converted).
    """
    triage_value = triage_values_mapping.get(triage_status, {})
    cx_state = triage_value.get('state')
    cx_severity = triage_value.get('severity', None)
    cx_score = triage_value.get('score', None)  # For CSEC, score is just the severity string from the mapping
    return cx_state, cx_severity, cx_score

def main(folder_path, column, sheet_name=None):

    logger = Logger(create_log_file=False)
    access_token_manager = AccessTokenManager(logger=logger)
    access_token = access_token_manager.get_valid_token()
    cx_api_actions = CxApiActions(access_token=access_token, logger=logger)
    helper = HelperFunctions()
    
    """
    Finds all Excel files in the given folder and processes each one.
    """
    excel_files = [
        f for f in os.listdir(folder_path)
        if f.lower().endswith(('.xlsx', '.xls'))
    ]

    if not excel_files:
        logger.info(f"No Excel files found in folder: {folder_path}")
        return

    for excel_file in excel_files:
        file_path = os.path.join(folder_path, excel_file)
        logger.info(f"Processing file: {excel_file}")

        try:
            # Always extract and log devsecops tool (B5) and IDs from B7
            devsecops_tool = ExcelReader.read_cells(
                file_path=file_path,
                column='B',
                row_start=5,
                row_end=5,
                sheet_name=sheet_name
            )

            devsecops_tool = devsecops_tool[0]
            if not devsecops_tool or not helper.is_readable(str(devsecops_tool)):
                logger.warning(f"The value of Desecops Tool (B5) is missing or unreadable")
            logger.info(f"Devsecops Tool: {devsecops_tool}")

            report_url = ExcelReader.read_cells(
                file_path=file_path,
                column='B',
                row_start=7,
                row_end=7,
                sheet_name=sheet_name
            )

            report_url = report_url[0]
            if not report_url or not helper.is_readable(str(report_url)):
                logger.warning(f"The value of DeSecOps Tool (B5) is missing or unreadable")

            ids = helper.extract_ids_from_result_url(report_url)
            project_id = ids.get('project_id')
            scan_id = ids.get('scan_id')

            logger.info(f"Extracted IDs from Report URL Field (B7)")
            logger.info(f"Project ID: {project_id}, Scan ID: {scan_id}")

            scan_type = str(devsecops_tool).strip().upper()
            # Unified scan type processing block
            if scan_type == "SAST":
                logger.info("Detected SAST scan type.")
                # SAST-specific processing here
                row_start, row_end = 7, 14
                logger.info("Using B7:B14 for SAST.")

                # JIRA to CX Mapping (example)
                sast_triage_values_mapping = {
                    "False Positive": {"state": "NOT_EXPLOITABLE"},
                    "Downgrade to High": {"state": "CONFIRMED", "severity": "HIGH"},
                    "Downgrade to Medium": {"state": "CONFIRMED", "severity": "MEDIUM"},
                    "Downgrade to Low": {"state": "CONFIRMED", "severity": "LOW"},
                }

                # Assign B8 to B14 to variables, log warnings for missing/unreadable values
                vuln_cells = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=8,
                    row_end=14,
                    sheet_name=sheet_name
                )

                triage_status = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=13,
                    row_end=13,
                    sheet_name=sheet_name
                )

                justification = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=14,
                    row_end=14,
                    sheet_name=sheet_name
                )

                cell_names = [
                    "vuln_id_1", "vuln_id_2", "vuln_id_3", "vuln_id_4", "vuln_id_5"
                ]

                values = {}
                for idx, name in enumerate(cell_names):
                    val = vuln_cells[idx] if len(vuln_cells) > idx else None
                    if not val or not helper.is_readable(str(val)):
                        logger.warning(f"SAST {name} (B{8+idx}) is missing or unreadable: {val}")
                        values[name] = None
                    else:
                        values[name] = val
                        logger.info(f"SAST {name} (B{8+idx}): {val}")

                vuln_id_1 = values["vuln_id_1"]
                vuln_id_2 = values["vuln_id_2"]
                vuln_id_3 = values["vuln_id_3"]
                vuln_id_4 = values["vuln_id_4"]
                vuln_id_5 = values["vuln_id_5"]
                triage_status = triage_status[0]
                justification = justification[0]

            elif scan_type == "SCA":
                logger.info("Detected SCA scan type.")
                # SCA-specific processing here
                row_start, row_end = 7, 11
                logger.info("Using B7:B11 for SCA.")
                # Place SCA-specific processing here

            elif scan_type == "CSEC":
                logger.info("Detected CSEC scan type.")
                # CSEC-specific processing here
                row_start, row_end = 7, 11
                logger.info("Using B7:B11 for CSEC.")
                # Place CSEC-specific processing here

            else:
                logger.warning(f"Unknown scan type in B5: {devsecops_tool}. Skipping file.")
                continue

            scan_details = cx_api_actions.get_scan_details(scan_id)
            if scan_details is None:
                raise ValueError(f"Scan ID {scan_id} is empty or does not exist")

            # values = ExcelReader.read_cells(
            #     file_path=file_path,
            #     column=column,
            #     row_start=row_start,
            #     row_end=row_end,
            #     sheet_name=sheet_name
            # )

            # logger.info(f"Values in column {column} rows {row_start} to {row_end}:")
            # for idx, val in enumerate(values, start=row_start):
            #     logger.info(f"{column}{idx}: {val}")

        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Process Excel files in jira_tickets/{date_folder} and read a dynamic cell range."
    )
    parser.add_argument("-date", "--date", required=True, help="Date-named subfolder inside jira_tickets (e.g., 21102025)")
    parser.add_argument("-col", "--column", default="B", help="Column letter or 0-based index to read (e.g., B or 1). Defaults to B if not specified.")
    parser.add_argument("-sheet", "--sheet_name", required=False, help="Optional sheet name (default: first sheet)")

    args = parser.parse_args()

    base_folder = os.path.join(os.getcwd(), "jira_tickets")
    folder_path = os.path.join(base_folder, args.date)

    # Accept both column letter and index
    try:
        column = int(args.column)
    except ValueError:
        column = args.column

    if not os.path.isdir(folder_path):
        print(f"Folder does not exist: {folder_path}")
        sys.exit(1)

    main(
        folder_path=folder_path,
        column=column,
        sheet_name=args.sheet_name
    )
