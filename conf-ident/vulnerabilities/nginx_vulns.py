from vulnerabilities.base_vulnerability import Vulnerability
#examples
class DirectoryListingVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Directory Listing Enabled",
            severity="medium",
            description="Directory listing is enabled, which allows attackers to view the contents of directories on your server.",
            recommendation="Disable directory listing by removing 'autoindex on' or setting it to 'autoindex off'."
        )

class NoRequestSizeLimitVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="No Request Size Limit",
            severity="medium",
            description="No request size limit is defined, which could allow attackers to perform denial of service attacks by sending large requests.",
            recommendation="Set a reasonable request size limit using 'client_max_body_size' directive."
        )

class UnsafePHPExecutionVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Unsafe PHP Execution Configuration",
            severity="high",
            description="The PHP configuration is vulnerable to file upload attacks that could lead to remote code execution.",
            recommendation="Add 'try_files $uri =404;' before the fastcgi_pass directive to prevent execution of non-existent PHP files."
        )
