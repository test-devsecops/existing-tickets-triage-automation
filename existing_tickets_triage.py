from utils.excel_reader import ExcelReader
from utils.logger import Logger
from utils.helper_functions import HelperFunctions
from checkmarx_utility.cx_api_actions import CxApiActions
from checkmarx_utility.cx_token_manager import AccessTokenManager

import os
import sys
import argparse
import math
import re

def _get_cx_state_severity_score(triage_values_mapping, triage_status):
    """
    For CSEC only: returns (state, severity, score) where score is the string from the mapping (not converted).
    """
    triage_value = triage_values_mapping.get(triage_status, {})
    cx_state = triage_value.get('state')
    cx_severity = triage_value.get('severity', None)
    cx_score = triage_value.get('score', None)  # For CSEC, score is just the severity string from the mapping
    return cx_state, cx_severity, cx_score

def main(folder_path, column, sheet_name=None, excel_file=None):

    log = Logger(create_log_file=False)
    access_token_manager = AccessTokenManager(logger=log)
    access_token = access_token_manager.get_valid_token()
    cx_api_actions = CxApiActions(access_token=access_token, logger=log)
    helper = HelperFunctions()
    
    """
    Finds all Excel files in the given folder and processes each one.
    If excel_file is provided, only process that file.
    """
    if excel_file:
        excel_files = [excel_file] if os.path.isfile(os.path.join(folder_path, excel_file)) else []
    else:
        excel_files = [
            f for f in os.listdir(folder_path)
            if f.lower().endswith(('.xlsx', '.xls'))
        ]

    if not excel_files:
        log.info(f"No Excel files found in folder: {folder_path}")
        return

    summary_rows = []
    for excel_file in excel_files:
        file_path = os.path.join(folder_path, excel_file)
        log.info(f"Processing file: {excel_file}")

        success_count = 0
        fail_count = 0

        try:
            jira_ticket_id = ExcelReader.read_cells(
                file_path=file_path,
                column='B',
                row_start=2,
                row_end=2,
                sheet_name=sheet_name
            )

            jira_ticket_id = jira_ticket_id[0]
            if helper.is_missing_or_unreadable(jira_ticket_id):
                log.warning(f"The value of JIRA Ticket ID Type (B2) is missing or unreadable")
                jira_ticket_id = None
                fail_count += 1
            log.info(f"Processing JIRA Ticket: {jira_ticket_id}")
            
            devsecops_type = ExcelReader.read_cells(
                file_path=file_path,
                column='B',
                row_start=5,
                row_end=5,
                sheet_name=sheet_name
            )

            devsecops_type = devsecops_type[0]
            if helper.is_missing_or_unreadable(devsecops_type):
                log.warning(f"The value of DevSecOps Type (B5) is missing or unreadable")
                scan_type = None
                fail_count += 1
            scan_type = str(devsecops_type).strip().upper()

            report_url = ExcelReader.read_cells(
                file_path=file_path,
                column='B',
                row_start=7,
                row_end=7,
                sheet_name=sheet_name
            )

            report_url = report_url[0]
            if helper.is_missing_or_unreadable(report_url):
                log.error(f"The value of Report URL (B7) is missing or unreadable. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id} - Unable to proceed for this file.")
                fail_count += 1
                continue

            ids = helper.extract_ids_from_result_url(report_url)
            project_id = ids.get('project_id')
            scan_id = ids.get('scan_id')

            log.success(f"Successfully extracted IDs from Report URL Cell (B7)")
            log.info(f"Project ID: {project_id}, Scan ID: {scan_id}")

            # Scan ID Verification
            scan_details_resp = cx_api_actions.get_scan_details(scan_id)
            if not scan_details_resp or not scan_details_resp.get('success'):
                log.skipped(f"Unable to process Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id} because of an error in Scan ID. Skipping processing for this file.")
                fail_count += 1
                continue
            scan_details = scan_details_resp.get("data", {})
            log.success(f"Scan ID {scan_id} is found.")
            project_name = scan_details.get('projectName')
 
            if scan_type == "SAST":
                log.info(f"DevSecOps Type: {scan_type}.")
                log.info("Using B7:B14 for SAST.")

                # Assign B8 to B14 to variables, log warnings for missing/unreadable values
                vuln_cells = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=8,
                    row_end=14,
                    sheet_name=sheet_name
                )

                cell_names = ["vuln_id_1", "vuln_id_2", "vuln_id_3", "vuln_id_4", "vuln_id_5"]
                values = {}

                all_vulns_missing = True
                for idx, name in enumerate(cell_names):
                    val = vuln_cells[idx] if len(vuln_cells) > idx else None
                    if helper.is_missing_or_unreadable(val):
                        log.warning(f"SAST {name} (B{8+idx}) is missing or unreadable: {val}")
                        fail_count += 1
                    else:
                        values[name] = val
                        log.info(f"SAST {name} (B{8+idx}): {val}")
                        all_vulns_missing = False

                if all_vulns_missing:
                    log.error(f"All SAST vulnerability IDs (B8:B12) are missing or unreadable for Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}. Unable to proceed for this file.")
                    fail_count += 1
                    continue

                triage_status = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=13,
                    row_end=13,
                    sheet_name=sheet_name
                )

                triage_status = triage_status[0]
                if helper.is_missing_or_unreadable(triage_status):
                    log.warning(f"The value of Triage Status (B13) is missing or unreadable")
                    fail_count += 1

                justification = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=14,
                    row_end=14,
                    sheet_name=sheet_name
                )
                
                justification = justification[0]
                if helper.is_missing_or_unreadable(justification):
                    log.warning(f"The value of Justification (B14) is missing or unreadable")
                    justification = None
                    fail_count += 1

                # JIRA to CX Mapping (example)
                sast_triage_values_mapping = {
                    "False Positive": {"state": "NOT_EXPLOITABLE"},
                    "Downgrade to High": {"state": "CONFIRMED", "severity": "HIGH"},
                    "Downgrade to Medium": {"state": "CONFIRMED", "severity": "MEDIUM"},
                    "Downgrade to Low": {"state": "CONFIRMED", "severity": "LOW"},
                }

                cx_state, cx_severity, cx_score = _get_cx_state_severity_score(sast_triage_values_mapping, triage_status)
                
                for vuln_id in values.values():
                    sast_scan_resp = cx_api_actions.get_sast_results(scan_id, vuln_id)

                    if not sast_scan_resp or not sast_scan_resp.get('success'):
                        log.error(f"Scan ID {scan_id} or Vulnerability ID {vuln_id} returned empty or does not exist. Unable to proceed for this file")
                        fail_count += 1
                        continue
                    
                    sast_scan = sast_scan_resp.get("data", {})
                    sast_scan_results = sast_scan.get('results')
                    if sast_scan_results is not None:
                        for result in sast_scan_results:
                            similarity_id = result.get('similarityID')
                            wrapped_similarity_id = helper.shorten_strings_middle(str(similarity_id))
                            log.info(f"Similarity ID: {wrapped_similarity_id}")

                            sast_predicate_resp = cx_api_actions.post_sast_predicates(similarity_id, project_id, scan_id, cx_severity, cx_state, justification)
                            if not sast_predicate_resp or not sast_predicate_resp.get('success'):
                                log.error(f"{scan_type} Failed to update the state and severity of Vulnerability ID: {wrapped_similarity_id} Scan ID: {scan_id} JIRA Ticket ID: {jira_ticket_id}")
                                fail_count += 1
                            else:
                                log.success(f"{scan_type} Successfully updated the state and severity of Vulnerability ID: {wrapped_similarity_id} to State: {cx_state} Severity: {cx_severity} JIRA Ticket: {jira_ticket_id}")
                                success_count += 1

            elif scan_type == "SCA":
                log.info(f"DevSecOps Type: {scan_type}.")
                log.info("Using B7:B11 for SCA.")
                
                package_name_version = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=8,
                    row_end=8,
                    sheet_name=sheet_name
                )

                package_name_version = package_name_version[0]
                if helper.is_missing_or_unreadable(package_name_version):
                    log.error(f"The value of Package Name - Version (B8) is missing or unreadable. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}. Unable to proceed for this file.")
                    fail_count += 1
                    continue
            
                cve_numbers = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=9,
                    row_end=9,
                    sheet_name=sheet_name
                )

                cve_numbers_raw = cve_numbers[0]
                if helper.is_missing_or_unreadable(cve_numbers_raw):
                    log.error(f"The value of CVE Numbers (B9) is missing or unreadable. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}. Unable to proceed for this file.")
                    fail_count += 1
                    continue

                # Convert CVE numbers to a list, splitting by comma or semicolon            
                cve_id_list = [cve.strip() for cve in re.split(r'[;,]', str(cve_numbers_raw)) if cve.strip()]
                log.info(f"CVE Numbers (B9) parsed as list: {cve_id_list}")

                triage_status = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=10,
                    row_end=10,
                    sheet_name=sheet_name
                )

                triage_status = triage_status[0]
                if helper.is_missing_or_unreadable(triage_status):
                    log.warning(f"The value of Triage Status (B13) is missing or unreadable")
                    triage_status = None
                    fail_count += 1

                justification = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=11,
                    row_end=11,
                    sheet_name=sheet_name
                )
                
                justification = justification[0]
                if helper.is_missing_or_unreadable(justification):
                    log.error(f"The value of Justification (B11) is missing or unreadable. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}. Unable to proceed for this file.")
                    fail_count += 1
                    continue

                # JIRA to CX Mapping
                sca_triage_values_mapping = {
                    "False Positive": {"state": "NotExploitable", "severity": "0.0"},
                    "Downgrade to High": {"state": "Confirmed", "severity": "7"},
                    "Downgrade to Medium": {"state": "Confirmed", "severity": "4"},
                    "Downgrade to Low": {"state": "Confirmed", "severity": "0.1"},
                }

                package_name, package_version = helper.set_package_and_version(package_name_version)
                cx_state, cx_severity, cx_score = _get_cx_state_severity_score(sca_triage_values_mapping, triage_status)

                for cve_id in cve_id_list:

                    sca_vuln_resp = cx_api_actions.get_sca_vulnerability_details_with_CVE_graphql(scan_id, project_id, package_name, package_version, cve_id)
                    if not sca_vuln_resp or not sca_vuln_resp.get('success'):
                        log.error(f"Scan ID {scan_id}, Package Name {cve_id} or Vulnerability ID {cve_id} returned empty or does not exist. Unable to proceed for this file")
                        fail_count += 1
                        continue
                    
                    sca_vuln_details = sca_vuln_resp.get("data", {})
                    cve_details = helper.get_nested(sca_vuln_details, ['data', 'vulnerabilitiesRisksByScanId', 'items'])
                    package_repo = cve_details[0].get('packageInfo').get('packageRepository')
                    package_id = cve_details[0].get('packageId')

                    change_state_action = cx_api_actions.post_sca_management_of_risk(package_name, package_version, package_repo, cve_id, project_id, 'ChangeState', cx_state, justification)
                    change_score_action = cx_api_actions.post_sca_management_of_risk(package_name, package_version, package_repo, cve_id, project_id, 'ChangeScore', cx_severity, justification)
                    
                    if (change_state_action and change_state_action.get('success')) and (change_score_action and change_score_action.get('success')):
                        log.info(f"[{scan_type}] Successfully updated the state and severity of Package: {package_id} to State: {cx_state} Severity: {cx_severity}")
                        success_count += 1
                    else:
                        log.error(f"[{scan_type}] Failed to update the state and severity of Package: {package_id}. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}. Unable to proceed for this file.")
                        fail_count += 1

            elif scan_type == "CSEC":
                log.info(f"DevSecOps Type: {scan_type}.")
                # CSEC-specific processing here
                row_start, row_end = 7, 11
                log.info("Using B7:B11 for CSEC.")
                
                package_name_version = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=8,
                    row_end=8,
                    sheet_name=sheet_name
                )

                package_name_version = package_name_version[0]
                if helper.is_missing_or_unreadable(package_name_version):
                    log.error(f"The value of Package Name - Version (B8) is missing or unreadable. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}. Unable to proceed for this file.")
                    fail_count += 1
                    continue
            
                cve_numbers = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=9,
                    row_end=9,
                    sheet_name=sheet_name
                )

                cve_numbers_raw = cve_numbers[0]
                if helper.is_missing_or_unreadable(cve_numbers_raw):
                    log.error(f"The value of CVE Numbers (B9) is missing or unreadable. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}. Unable to proceed for this file.")
                    fail_count += 1
                    continue

                # Convert CVE numbers to a list, splitting by comma or semicolon            
                cve_id_list = [cve.strip() for cve in re.split(r'[;,]', str(cve_numbers_raw)) if cve.strip()]
                log.info(f"CVE Numbers (B9) parsed as list: {cve_id_list}")

                triage_status = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=10,
                    row_end=10,
                    sheet_name=sheet_name
                )

                triage_status = triage_status[0]
                if helper.is_missing_or_unreadable(triage_status):
                    log.warning(f"The value of Triage Status (B13) is missing or unreadable")
                    triage_status = None
                    fail_count += 1

                justification = ExcelReader.read_cells(
                    file_path=file_path,
                    column='B',
                    row_start=11,
                    row_end=11,
                    sheet_name=sheet_name
                )
                
                justification = justification[0]
                if helper.is_missing_or_unreadable(justification):
                    log.error(f"The value of Justification (B11) is missing or unreadable. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}. Unable to proceed for this file.")
                    fail_count += 1
                    continue
                    
                # JIRA to CX Mapping
                csec_triage_values_mapping = {
                    "False Positive": {"state": "NotExploitable"},
                    "Downgrade to High": {"state": "Confirmed", "severity": "High", "score": 7},
                    "Downgrade to Medium": {"state": "Confirmed", "severity": "Medium", "score": 4},
                    "Downgrade to Low": {"state": "Confirmed", "severity": "Low", "score": 0.1},
                }

                base_image_resp = cx_api_actions.get_image_id_graphql(scan_id, project_id)
                if not base_image_resp or not base_image_resp.get('success'):
                    log.error(f"Scan ID {scan_id} returned empty or does not exist. Unable to proceed for this file")
                    fail_count += 1
                    continue

                base_image_details = base_image_resp.get("data", {})
                base_image = helper.get_nested(base_image_details, ['data', 'images', 'items'])
                image_id = base_image[0].get('imageId')

                package_name, package_version = helper.set_package_and_version(package_name_version)
                cx_state, cx_severity, cx_score = _get_cx_state_severity_score(csec_triage_values_mapping, triage_status)

                csec_vuln_details_resp = cx_api_actions.get_csec_vulnerability_details_graphql(scan_id, project_id, image_id, package_name_version)
                if not csec_vuln_details_resp or not csec_vuln_details_resp.get('success'):
                    log.error(f"CSEC Vulnerability Details with Scan ID {scan_id} or Image ID {image_id} returned empty or does not exist. Unable to proceed for this file")
                    fail_count += 1
                    continue

                csec_vuln_details = csec_vuln_details_resp.get("data", {})
                image_vuln_details_count = helper.get_nested(csec_vuln_details, ['data', 'imagesVulnerabilities', 'totalCount'])
                if image_vuln_details_count == 0:
                    log.error(f"CSEC Vulnerability Details with Scan ID {scan_id} or Image ID {image_id} returned empty or does not exist. Unable to proceed for this file")
                    fail_count += 1
                    continue

                image_vuln_details = helper.get_nested(csec_vuln_details, ['data', 'imagesVulnerabilities', 'items'])
                vuln_item_id = image_vuln_details[0].get('id')
                package_id = image_vuln_details[0].get('packageId')

                for cve_id in cve_id_list:
                
                    csec_triage_vuln_update = cx_api_actions.post_csec_vulnerability_triage_update(cx_state, cx_severity, cx_score, justification, scan_id, project_id, vuln_item_id, cve_id)
                    if csec_triage_vuln_update and csec_triage_vuln_update.get('success'):
                        log.success(f"[{scan_type}] Successfully updated the state and severity of Package: {package_id} to State: {cx_state} Severity: {cx_severity}.")
                        success_count += 1
                    else:
                        log.error(f"[{scan_type}] Failed to update the state and severity of Package: {package_id}. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}. Unable to proceed for this file.")
                        fail_count += 1
            else:
                log.warning(f"Unknown scan type in B5: {devsecops_type}. Skipping file.")
                continue

            scan_details = cx_api_actions.get_scan_details(scan_id)
            if scan_details is None:
                raise ValueError(f"Scan ID {scan_id} is empty or does not exist")

            # Summary log after processing all vulnerabilities in the file
            if success_count > 0 and fail_count == 0:
                log.success(f"Successfully processed with no failures. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}")
                summary_status = "Successful"
            elif success_count > 0 and fail_count > 0:
                log.warning(f"Successfully processed but with some warnings. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}")
                summary_status = "Successful with warnings"
            elif success_count == 0 and fail_count > 0:
                log.error(f"Totally failed the process. Excel sheet: {excel_file} - JIRA Ticket: {jira_ticket_id}")
                summary_status = "Failed"

            summary_rows.append({
                "excel_file": excel_file,
                "jira_ticket_id": jira_ticket_id,
                "status": summary_status
            })

        except Exception as e:
            log.error(f"Error reading {file_path}: {e}")
            summary_rows.append({
                "excel_file": excel_file,
                "jira_ticket_id": jira_ticket_id,
                "status": "Failed"
            })
            continue

    # Write summary to markdown file for GitHub Actions summary
    if summary_rows:
        summary_md = "| Excel File | JIRA Ticket | Status |\n|---|---|---|\n"
        for row in summary_rows:
            summary_md += f"| {row['excel_file']} | {row['jira_ticket_id']} | {row['status']} |\n"
        with open("triage_run_summary.md", "w") as f:
            f.write(summary_md)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Process Excel files in jira_tickets/{date_folder} and read a dynamic cell range."
    )
    parser.add_argument("-date", "--date", required=False, help="Date-named subfolder inside jira_tickets (e.g., 21102025)")
    parser.add_argument("-col", "--column", default="B", help="Column letter or 0-based index to read (e.g., B or 1). Defaults to B if not specified.")
    parser.add_argument("-sheet", "--sheet_name", required=False, help="Optional sheet name (default: first sheet)")
    parser.add_argument("--excel_file", required=False, help="Optional Excel file to process (e.g., ticket.xlsx)")

    args = parser.parse_args()

    # If date is not provided, use today's date in yyyymmdd format
    date_value = args.date if args.date else HelperFunctions.get_today_date_yyyymmdd()
    base_folder = os.path.join(os.getcwd(), "jira_tickets")
    folder_path = os.path.join(base_folder, date_value)

    # Accept both column letter and index
    try:
        column = int(args.column)
    except ValueError:
        column = args.column

    if not os.path.isdir(folder_path):
        print(f"Folder does not exist: {folder_path}")
        sys.exit(1)

    # If excel_file is provided, process only that file
    if args.excel_file:
        file_path = os.path.join(folder_path, args.excel_file)
        if not os.path.isfile(file_path):
            print(f"Excel file does not exist: {file_path}")
            sys.exit(1)
        main(
            folder_path=folder_path,
            column=column,
            sheet_name=args.sheet_name,
            excel_file=args.excel_file
        )
    else:
        main(
            folder_path=folder_path,
            column=column,
            sheet_name=args.sheet_name,
            excel_file=None
        )
