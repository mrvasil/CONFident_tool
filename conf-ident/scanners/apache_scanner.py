import os
import re
from scanners.base_scanner import BaseScanner
from vulnerabilities.apache_vulns import (
    DirectoryIndexingVulnerability,
    UnrestrictedCGIExecutionVulnerability,
    AllowAllHtaccessVulnerability
)

class ApacheScanner(BaseScanner):
    def __init__(self, config_path=None):
        super().__init__(config_path)
        self.default_paths = [
            '/etc/apache2/apache2.conf',
            '/etc/apache2/sites-enabled/',
            '/etc/httpd/conf/httpd.conf',
            '/usr/local/apache2/conf/httpd.conf'
        ]
    
    def find_config_files(self):
        config_files = []
        
        if self.config_path:
            if os.path.isfile(self.config_path):
                config_files.append(self.config_path)
            elif os.path.isdir(self.config_path):
                for root, _, files in os.walk(self.config_path):
                    for file in files:
                        if file.endswith('.conf'):
                            config_files.append(os.path.join(root, file))
        else:
            for path in self.default_paths:
                if os.path.isfile(path):
                    config_files.append(path)
                elif os.path.isdir(path):
                    for file in os.listdir(path):
                        if file.endswith('.conf'):
                            config_files.append(os.path.join(path, file))
        
        return config_files
    
    def parse_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading config file {config_file}: {e}")
            return ""
    
    def check_vulnerabilities(self, config_data, config_file):
        self._check_directory_indexing(config_data, config_file)
        self._check_unrestricted_cgi(config_data, config_file)
        self._check_htaccess_permissions(config_data, config_file)
    

    #Vulnerabilities
    def _check_directory_indexing(self, config_data, config_file):
        pattern = r'Options\s+.*Indexes.*'
        matches = re.finditer(pattern, config_data)
        
        line_numbers = []
        for match in matches:
            line_number = config_data[:match.start()].count('\n') + 1
            line_numbers.append(line_number)
        
        if line_numbers:
            vuln = DirectoryIndexingVulnerability()
            vuln.add_affected_file(config_file, line_numbers)
            self.vulnerabilities.append(vuln)
    
    def _check_unrestricted_cgi(self, config_data, config_file):
        cgi_pattern = r'Options\s+.*\+ExecCGI.*'
        handler_pattern = r'AddHandler\s+cgi-script'
        
        if re.search(cgi_pattern, config_data) and re.search(handler_pattern, config_data):
            vuln = UnrestrictedCGIExecutionVulnerability()
            
            line_numbers = []
            for match in re.finditer(cgi_pattern, config_data):
                line_number = config_data[:match.start()].count('\n') + 1
                line_numbers.append(line_number)
            
            for match in re.finditer(handler_pattern, config_data):
                line_number = config_data[:match.start()].count('\n') + 1
                line_numbers.append(line_number)
            
            vuln.add_affected_file(config_file, line_numbers)
            self.vulnerabilities.append(vuln)
    
    def _check_htaccess_permissions(self, config_data, config_file):
        pattern = r'AllowOverride\s+All'
        matches = re.finditer(pattern, config_data)
        
        line_numbers = []
        for match in matches:
            line_number = config_data[:match.start()].count('\n') + 1
            line_numbers.append(line_number)
        
        if line_numbers:
            vuln = AllowAllHtaccessVulnerability()
            vuln.add_affected_file(config_file, line_numbers)
            self.vulnerabilities.append(vuln)
