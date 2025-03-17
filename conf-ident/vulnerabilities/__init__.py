from vulnerabilities.base_vulnerability import Vulnerability
from vulnerabilities.nginx_vulns import (
    DirectoryListingVulnerability,
    NoRequestSizeLimitVulnerability,
    UnsafePHPExecutionVulnerability
)
from vulnerabilities.apache_vulns import (
    DirectoryIndexingVulnerability,
    UnrestrictedCGIExecutionVulnerability,
    AllowAllHtaccessVulnerability
)
