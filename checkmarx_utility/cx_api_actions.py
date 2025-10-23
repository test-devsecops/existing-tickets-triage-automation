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
    
    def post_sast_predicates(self, similarity_id, project_id, scan_id, severity, state, comment):

        endpoint = self.apiEndpoints.sast_predicates()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        json_payload = [
            {
                "similarityId": str(similarity_id),
                "projectId": project_id,
                "scanId": scan_id,
                "severity": severity,
                "state": state,
                "comment": comment
            }
        ]

        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response
    
    def get_sca_vulnerability_details_with_CVE_graphql(self, scan_id, project_id, vuln_id, version, cve_id):

        endpoint = self.apiEndpoints.sca_vuln_details_graphql()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0",
            "cx-authentication-type": "service",
            "cx-project-id": project_id
        }

        json_payload = {
            "query": "query GetVulnerabilitiesByScanId ($scanId: UUID!, $take: Int!, $skip: Int!, $order: [VulnerabilitiesSort!], $where: VulnerabilityModelFilterInput, $isExploitablePathEnabled: Boolean!) {\n  vulnerabilitiesRisksByScanId (\n    scanId: $scanId,\n    take: $take,\n    skip: $skip,\n    order: $order,\n    where: $where,\n    isExploitablePathEnabled: $isExploitablePathEnabled\n  ) {\n    totalCount\n    items {\n      credit\n      state\n      isIgnored\n      cve\n      cwe\n      description\n      packageId\n      severity\n      type\n      published\n      score\n      violatedPolicies\n      isExploitable\n      exploitabilityReason\n      exploitabilityStatus\n      isKevDataExists\n      isExploitDbDataExists\n      vulnerabilityFixResolutionText\n      relation\n      epssData {\n        cve\n        date\n        epss\n        percentile\n      }\n      isEpssDataExists\n      detectionDate\n      isVulnerabilityNew\n      cweInfo {\n        title\n      }\n      packageInfo {\n        name\n        packageRepository\n        version\n      }\n      exploitablePath {\n        methodMatch {\n          fullName\n          line\n          namespace\n          shortName\n          sourceFile\n        }\n        methodSourceCall {\n          fullName\n          line\n          namespace\n          shortName\n          sourceFile\n        }\n      }\n      vulnerablePackagePath {\n        id\n        isDevelopment\n        isResolved\n        name\n        version\n        vulnerabilityRiskLevel\n      }\n      references {\n        comment\n        type\n        url\n      }\n      cvss2 {\n        attackComplexity\n        attackVector\n        authentication\n        availability\n        availabilityRequirement\n        baseScore\n        collateralDamagePotential\n        confidentiality\n        confidentialityRequirement\n        exploitCodeMaturity\n        integrityImpact\n        integrityRequirement\n        remediationLevel\n        reportConfidence\n        targetDistribution\n      }\n      cvss3 {\n        attackComplexity\n        attackVector\n        availability\n        availabilityRequirement\n        baseScore\n        confidentiality\n        confidentialityRequirement\n        exploitCodeMaturity\n        integrity\n        integrityRequirement\n        privilegesRequired\n        remediationLevel\n        reportConfidence\n        scope\n        userInteraction\n      }\n      cvss4 {\n        attackComplexity\n        attackVector\n        attackRequirements\n        baseScore\n        privilegesRequired\n        userInteraction\n        vulnerableSystemConfidentiality\n        vulnerableSystemIntegrity\n        vulnerableSystemAvailability\n        subsequentSystemConfidentiality\n        subsequentSystemIntegrity\n        subsequentSystemAvailability\n      }\n      pendingState\n      pendingChanges\n      packageState {\n        type\n        value\n      }\n      pendingScore\n      pendingSeverity\n      isScoreOverridden\n    }\n  }\n}",
            "variables": {
                "scanId": scan_id,
                "take": 10,
                "skip": 0,
                "order": [
                    { "score": "DESC" }
                ],
                "where": {
                "and": [
                    { "cve": { "eq": cve_id } },
                    { "packageInfo": {
                        "and": [
                        { "name": { "eq": vuln_id } },
                        { "version": { "eq": version } }
                        ]
                    }
                    }
                ]
                },
                "isExploitablePathEnabled": True
            }
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response
    
    def post_sca_management_of_risk(self, package_name, package_version, package_repo, cve_id, project_id, action_type, value, comment):

        endpoint = self.apiEndpoints.sca_management_of_risk()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        json_payload = {
            "packageName": package_name,
            "packageVersion": package_version,
            "packageManager": package_repo,
            "vulnerabilityId": cve_id,
            "projectIds":[
                project_id
            ],
            "actions":[
                {
                    "actionType":action_type,
                    "value": value,
                    "comment": comment
                }
            ]
        }
        
        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response
    
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
    
    def get_csec_vulnerability_details_graphql(self, scan_id, project_id, image_id, package_id):

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
            "query": "query GetImagesVulnerabilities ($scanId: UUID!, $imageId: String, $take: Int, $skip: Int, $searchTerm: String, $order: [PackageVulnerabilityTypeSortInput!], $where: PackageVulnerabilityTypeFilterInput, $vulnerabilityFilter: VulnerabilityFilterInput) { imagesVulnerabilities (scanId: $scanId, imageId: $imageId, take: $take, skip: $skip, searchTerm: $searchTerm, order: $order, where: $where, vulnerabilityFilter: $vulnerabilityFilter) { totalCount items { packageName distribution type packageVersion packageId runtimeUsage isMalicious risksCount status snoozeDate id aggregatedRisks { critical high medium low none risksList { cve vulnerabilityLevel vulnerabilityScore description publicationDate fixedVersion state originalSeverityLevel } } binaryList { version name } } } }",
            "variables": {
                "scanId": scan_id,
                "imageId": image_id,
                "take": 10,
                "skip": 0,
                "searchTerm": "",
                "order": [
                { "isMalicious": "ASC" },
                { "runtimeUsage": "ASC" },
                { "aggregatedRisks": { "critical": "DESC", "high": "DESC", "medium": "DESC", "low": "DESC", "none": "DESC" } }
                ],
                "where": {
                    "packageId": {
                        "eq": package_id
                    }
                },
                "vulnerabilityFilter": {
                "fromScore": 0,
                "toScore": 10
                }
            }
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response
    
    def post_csec_vulnerability_triage_update(self, state, severity, score, comment, scan_id, project_id, vuln_item_id, cve_id):

        endpoint = self.apiEndpoints.csec_vulnerability_triage_update()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        json_payload = {
            "state":state,
            "severity":severity,
            "score":score,
            "comment": comment,
            "scanId":scan_id,
            "projectId":project_id,
            "triages":[
                {
                    "packageId": vuln_item_id,
                    "cveId": cve_id
                }
            ],
            "group":"vulnerabilities"
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response
