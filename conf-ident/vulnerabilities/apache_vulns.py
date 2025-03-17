from vulnerabilities.base_vulnerability import Vulnerability

class DirectoryIndexingVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Directory Indexing Enabled",
            severity="medium",
            description="Directory indexing is enabled, which allows attackers to view the contents of directories on your server.",
            recommendation="Remove 'Indexes' from the Options directive or use 'Options -Indexes' to explicitly disable it."
        )

class UnrestrictedCGIExecutionVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Unrestricted CGI Execution",
            severity="high",
            description="CGI script execution is enabled without proper restrictions, which could allow attackers to execute malicious code on the server.",
            recommendation="Limit CGI execution to specific directories and implement proper access controls. Consider using 'ScriptAlias' for CGI directories."
        )

class AllowAllHtaccessVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Unrestricted .htaccess Usage",
            severity="medium",
            description="'AllowOverride All' allows .htaccess files to override any directive, which could lead to security issues if these files are compromised.",
            recommendation="Use 'AllowOverride None' or specify only the necessary override categories (e.g., 'AllowOverride AuthConfig Indexes')."
        )
