class CxApiEndpoints:

    @staticmethod
    def openid_token(tenant_name):
        endpoint = f"/auth/realms/{tenant_name}/protocol/openid-connect/token"
        return endpoint
    
    @staticmethod
    def projects():
        endpoint = "/api/projects/"
        return endpoint
    
    @staticmethod
    def scan_details(scan_id):
        endpoint = f"/api/scans/{scan_id}"
        return endpoint
    
    @staticmethod
    def sast_results():
        endpoint = f"/api/sast-results"
        return endpoint
    
    # ---------------------------------------

    @staticmethod
    def sca_update_package():
        endpoint = "/api/sca/management-of-risk/packages/bulk"
        return endpoint
    
    @staticmethod
    def sca_vuln_details_graphql():
        endpoint = "/api/sca/graphql/graphql"
        return endpoint
    
    @staticmethod
    def project_latest_scan():
        endpoint = "/api/projects/last-scan"
        return endpoint
    
    @staticmethod
    def csec_package_update():
        endpoint = "/api/containers/triage/triage/package-update"
        return endpoint
    
    @staticmethod
    def csec_vuln_details_graphql():
        endpoint = f"/api/containers/buffet/graphql"
        return endpoint
    
    @staticmethod
    def sca_recalculate():
        endpoint = "/api/scans/recalculate"
        return endpoint
