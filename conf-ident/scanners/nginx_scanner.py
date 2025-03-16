import os
from typing import List, Dict, Any, Optional

from scanners.base_scanner import BaseScanner
from parsers.nginx_parser import NginxParser
from config.nginx_default_paths import DEFAULT_NGINX_PATHS
from utils.config_finder import find_config_files
from rules.nginx_rules.ssl_rules import SSLRules
from rules.nginx_rules.access_rules import AccessRules
from rules.nginx_rules.headers_rules import HeadersRules

class NginxScanner(BaseScanner):
    
    def __init__(self, config_path: Optional[str] = None):
        super().__init__(config_path)
        self.parser = NginxParser()
        
        self.rules = [
            SSLRules(),
            AccessRules(),
            HeadersRules()
        ]
    
    def find_config_files(self) -> List[str]:
        if self.config_path:
            return find_config_files(self.config_path, "*.conf")

        all_files = []
        for path in DEFAULT_NGINX_PATHS:
            if os.path.exists(path):
                files = find_config_files(path, "*.conf")
                all_files.extend(files)
        
        return all_files
    
    def parse_config(self, config_file: str) -> Dict[str, Any]:
        return self.parser.parse(config_file)
    
    def check_vulnerabilities(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        for rule in self.rules:
            rule_vulns = rule.check(config)
            vulnerabilities.extend(rule_vulns)
        
        return vulnerabilities