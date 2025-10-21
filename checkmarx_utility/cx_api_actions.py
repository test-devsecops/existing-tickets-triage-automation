from checkmarx_utility.cx_api_endpoints import CxApiEndpoints
from checkmarx_utility.cx_config_utility import Config

from utils.exception_handler import ExceptionHandler
from utils.http_utility import HttpRequests

import sys

class CxApiActions:

    def __init__(self, access_token, logger):
        self.httpRequest = HttpRequests(logger)
        self.apiEndpoints = CxApiEndpoints()
        self.logger = logger
        self.access_token = access_token
        self.config = Config()

        self.token, self.tenant_name, self.tenant_iam_url, self.tenant_url = self.config.get_config()
    
    @ExceptionHandler.handle_exception()
    def get_projects(self, empty_tag="false", project_name=None):

        endpoint = self.apiEndpoints.projects()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        limit = 100  
        offset = 0   
        all_projects = []

        while True:
            params = {
                "limit": limit,
                "offset": offset,
                "empty-tags": empty_tag
            }

            if project_name is not None:
                params["name-regex"] = f"(?i)^{project_name}$"

            response = self.httpRequest.get_api_request(url, headers=headers, params=params)
            
            # Must include the required key
            if "projects" not in response:
                raise KeyError("Missing 'projects' key in API response")

            # Must be the right type
            if not isinstance(response["projects"], list):
                raise TypeError(f"Expected 'projects' to be a list, got {type(response["projects"]).__name__}")

            # semantic/business validation
            if not response["projects"]:
                raise ValueError("Expected at least one project in 'projects'")

            all_projects.extend(response["projects"])

            if len(response["projects"]) < limit:
                break  

            offset += limit

        return all_projects
    
    @ExceptionHandler.handle_exception
    def get_scan_details(self, scan_id):

        endpoint = self.apiEndpoints.scan_details(scan_id)
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        response = self.httpRequest.get_api_request(url, headers=headers)
        return response

    @ExceptionHandler.handle_exception
    def get_sast_results(self, scan_id, vuln_id=None):
        """
        Fetch SAST results for one or more vulnerability IDs.

        Args:
            scan_id (str): The SAST scan ID.
            vuln_id (str or list, optional): A single vulnerability ID or a list of IDs.

        Returns:
            Response object from the API request.
        """
        endpoint = self.apiEndpoints.sast_results()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        # Support multiple result-id query params
        if isinstance(vuln_id, list):
            params = [("scan-id", scan_id)] + [("result-id", vid) for vid in vuln_id]
        else:
            params = {
                "scan-id": scan_id,
                "result-id": vuln_id
            }

        response = self.httpRequest.get_api_request(url, headers=headers, params=params)
        return response
    
    # ---------------------- Not Being Used --------------------------------

    @ExceptionHandler.handle_exception(reraise=True, log_error=False)
    def post_sca_update_package_state(self, packages_profile : list, action_type, state_value, end_date, comment=None):
        endpoint = self.apiEndpoints.sca_update_package()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        json_payload = {
            "packagesProfile":packages_profile,
            "actions":[
                {
                    "actionType":action_type, #Ignore
                    "value":{
                        "state": state_value, # Snooze, Monitored
                        "endDate":end_date # 2025-10-22T07:43:52.044Z
                    },
                    "comment": comment
                }
            ]
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response
    
    @ExceptionHandler.handle_exception(reraise=True, log_error=False)
    def get_sca_vuln_details_by_package_name_version(self, package_name, package_version):

        endpoint = self.apiEndpoints.sca_vuln_details_graphql()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        json_payload = {
                "query": "query ($where: ReportingPackageModelFilterInput, $take: Int!, $skip: Int!, $order: [ReportingPackageModelSortInput!]) { reportingPackages (where: $where, take: $take, skip: $skip, order: $order) { packageId packageName packageVersion packageRepository outdated releaseDate newestVersion newestVersionReleaseDate numberOfVersionsSinceLastUpdate effectiveLicenses licenses projectName projectId scanId aggregatedCriticalVulnerabilities aggregatedHighVulnerabilities aggregatedMediumVulnerabilities aggregatedLowVulnerabilities aggregatedNoneVulnerabilities aggregatedCriticalSuspectedMalwares aggregatedHighSuspectedMalwares aggregatedMediumSuspectedMalwares aggregatedLowSuspectedMalwares aggregatedNoneSuspectedMalwares relation isDevDependency isTest isNpmVerified isPluginDependency isPrivateDependency tags scanDate status statusValue isMalicious usage isFixAvailable fixRecommendationVersion pendingStatus pendingStatusEndDate } }",
                "variables": {
                    "where": {
                    "and": [
                        { "packageName": { "eq": package_name } },
                        { "packageVersion": { "eq": package_version } }
                    ]
                    },
                    "take": 10,
                    "skip": 0
                }
            }

        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response
    
    @ExceptionHandler.handle_exception()
    def get_project_latest_scan_by_branch(self, project_ids : list, branch):

        endpoint = self.apiEndpoints.project_latest_scan()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        params = {
            "branch": branch,
            "project-ids": project_ids
        }

        response = self.httpRequest.get_api_request(url, headers=headers, params=params)
        return response
    
    @ExceptionHandler.handle_exception()
    def post_csec_update_package(self, project_id, package_ids:list, status, end_date, scan_id, image_id=None, comment=None):

        endpoint = self.apiEndpoints.csec_package_update()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        json_payload = {
            "comment": comment,
            "status": status,
            "snoozeEndDate": end_date,
            "imageId": image_id,
            "projectId": project_id,
            "packageIds":package_ids,
            "scanId": scan_id,
            "group":"packages"
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response
    
    @ExceptionHandler.handle_exception(reraise=True, log_error=False)
    def get_image_id_graphql(self, scan_id, project_id):

        endpoint = self.apiEndpoints.csec_vuln_details_graphql()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0",
            "cx-authentication-type": "service",
            "cx-project-id": project_id
        }

        json_payload = {
            "query": "query GetTableFilesData ($scanId: UUID!, $take: Int, $skip: Int, $includeRuntimeData: Boolean) { images (scanId: $scanId, take: $take, skip: $skip, includeRuntimeData: $includeRuntimeData) { totalCount, items { baseImage, fixable, imageId, imageName, isImageMalicious, maliciousDescription, maliciousPackagesCount, pkgCount, vulnerablePkgCount, runtime, scanError, severity, size, status, snoozeDate, vulnerabilities { criticalCount, highCount, mediumCount, lowCount, noneCount }, groupsData { fileName, filePath } } } }",
            "variables": {
                "scanId": scan_id,
                "take": 100,
                "skip": 0,
                "includeRuntimeData": False
            }
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response

    @ExceptionHandler.handle_exception()
    def get_csec_package_id_graphql(self, scan_id, project_id, image_id, package_id):

        endpoint = self.apiEndpoints.csec_vuln_details_graphql()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0",
            "cx-authentication-type": "service",
            "cx-project-id": project_id
        }

        json_payload = {
            "query": "query GetImagesVulnerabilities($scanId: UUID!, $imageId: String, $where: PackageVulnerabilityTypeFilterInput) { imagesVulnerabilities(scanId: $scanId, imageId: $imageId, where: $where) { items { id } } }",
            "variables": {
                "scanId": scan_id,
                "imageId": image_id,
                "where": {
                "packageId": {
                    "eq": package_id
                }
                }
            }
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response
    
    @ExceptionHandler.handle_exception(reraise=True, log_error=False)
    def post_sca_recalculate(self, project_id, branch):

        endpoint = self.apiEndpoints.sca_recalculate()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        json_payload = {
            "project_id": project_id,
            "branch": branch,
            "engines": [
                "sca"
            ],
            "config": [
                {
                    "type": "sca",
                    "value": {
                        "enableContainersScan": False
                    }
                }
            ]
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response
