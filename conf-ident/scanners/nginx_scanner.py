import os
import re
from scanners.base_scanner import BaseScanner
from vulnerabilities.nginx_vulns import (
    DirectoryListingVulnerability,
    NoRequestSizeLimitVulnerability,
    UnsafePHPExecutionVulnerability,
    MIMESniffingVulnerability,
    ClickjackingVulnerability,
    SSLTLSMisconfigurationVulnerability
)

class NginxScanner(BaseScanner):
    def __init__(self, config_path=None):
        super().__init__(config_path)
        self.default_paths = [
            '/etc/nginx/nginx.conf',
            '/etc/nginx/conf.d/',
            '/usr/local/nginx/conf/nginx.conf',
            '/usr/local/etc/nginx/nginx.conf'
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
        self._check_directory_listing(config_data, config_file)
        self._check_request_size_limit(config_data, config_file)
        self._check_php_execution(config_data, config_file)
        self._check_mime_sniffing(config_data, config_file)
        self._check_clickjacking(config_data, config_file)
        self._check_ssl_tls_config(config_data, config_file)
    

    #Vulnerabilities
    def _check_directory_listing(self, config_data, config_file):
        pattern = r'autoindex\s+on\s*;'
        matches = re.finditer(pattern, config_data)
        
        line_numbers = []
        for match in matches:
            line_number = config_data[:match.start()].count('\n') + 1
            line_numbers.append(line_number)
        
        if line_numbers:
            vuln = DirectoryListingVulnerability()
            vuln.add_affected_file(config_file, line_numbers)
            self.vulnerabilities.append(vuln)
    
    def _check_request_size_limit(self, config_data, config_file):
        client_max_body_size_pattern = r'client_max_body_size'
        if not re.search(client_max_body_size_pattern, config_data):
            vuln = NoRequestSizeLimitVulnerability()
            vuln.add_affected_file(config_file)
            self.vulnerabilities.append(vuln)
    
    def _check_php_execution(self, config_data, config_file):
        php_pattern = r'location ~ \.php$'
        fastcgi_pattern = r'fastcgi_param\s+SCRIPT_FILENAME'
        try_files_pattern = r'try_files\s+\$uri\s+=404'

        if (php_pattern in config_data) and re.search(fastcgi_pattern, config_data):
            print("PHP execution vulnerability detected")
            if not re.search(try_files_pattern, config_data):
                vuln = UnsafePHPExecutionVulnerability()
                #line_number = config_data.count('\n', 0, re.search(php_pattern, config_data).start()) + 1
                vuln.add_affected_file(config_file)
                self.vulnerabilities.append(vuln)
    
    def _find_closing_brace(self, text):
        count = 0
        for i, char in enumerate(text):
            if char == '{':
                count += 1
            elif char == '}':
                count -= 1
                if count == 0:
                    return i
        return -1

    def _check_mime_sniffing(self, config_data, config_file):
        nosniff_pattern = r'add_header\s+X-Content-Type-Options\s+nosniff'
        if not re.search(nosniff_pattern, config_data):
            vuln = MIMESniffingVulnerability()
            vuln.add_affected_file(config_file)
            self.vulnerabilities.append(vuln)

    def _check_clickjacking(self, config_data, config_file):
        xframe_pattern = r'add_header\s+X-Frame-Options\s+(DENY|SAMEORIGIN)'
        if not re.search(xframe_pattern, config_data):
            vuln = ClickjackingVulnerability()
            vuln.add_affected_file(config_file)
            self.vulnerabilities.append(vuln)

    def _check_ssl_tls_config(self, config_data, config_file):
        ssl_protocols_pattern = r'ssl_protocols\s+[^;]*;'
        ssl_ciphers_pattern = r'ssl_ciphers\s+[^;]*;'
        
        has_vulnerability = False
        line_numbers = []

        if re.search(r'ssl_protocols[^;]*SSLv2', config_data) or re.search(r'ssl_protocols[^;]*SSLv3', config_data) or re.search(r'ssl_protocols[^;]*TLSv1(\s|;)', config_data):
            has_vulnerability = True
            for match in re.finditer(ssl_protocols_pattern, config_data):
                line_numbers.append(config_data[:match.start()].count('\n') + 1)

        weak_ciphers = r'(RC4|MD5|DES|3DES|aNULL|eNULL)'
        if re.search(f'ssl_ciphers[^;]*{weak_ciphers}', config_data):
            has_vulnerability = True
            for match in re.finditer(ssl_ciphers_pattern, config_data):
                line_numbers.append(config_data[:match.start()].count('\n') + 1)

        if has_vulnerability:
            vuln = SSLTLSMisconfigurationVulnerability()
            vuln.add_affected_file(config_file, line_numbers)
            self.vulnerabilities.append(vuln)
