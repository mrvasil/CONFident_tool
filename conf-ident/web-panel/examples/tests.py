import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import parse_arguments, main
from scanners.nginx_scanner import NginxScanner
from vulnerabilities.nginx_vulns import DirectoryListingVulnerability

def test_parse_arguments():
    with patch('sys.argv', ['script.py', '--server-type', 'nginx']):
        args = parse_arguments()
        assert args.server_type == 'nginx'
        assert args.output == 'console'
        assert args.config_path is None

def test_nginx_scanner_init():
    scanner = NginxScanner()
    assert scanner.config_path is None
    assert len(scanner.default_paths) > 0

    custom_path = '/custom/path'
    scanner_with_path = NginxScanner(config_path=custom_path)
    assert scanner_with_path.config_path == custom_path

def test_nginx_scanner_directory_listing_vulnerability():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf') as temp_file:
        config_content = '''
server {
    listen 80;
    server_name example.com;
    location /files {
        autoindex on;
    }
}
'''
        temp_file.write(config_content)
        temp_file.flush()

        scanner = NginxScanner(config_path=temp_file.name)
        config_data = scanner.parse_config(temp_file.name)
        scanner._check_directory_listing(config_data, temp_file.name)
        
        assert len(scanner.vulnerabilities) == 1
        assert isinstance(scanner.vulnerabilities[0], DirectoryListingVulnerability)

def test_main_with_no_vulnerabilities():
    with patch('scanners.nginx_scanner.NginxScanner') as mock_scanner:
        instance = mock_scanner.return_value
        instance.scan.return_value = []
        instance.scanned_files_count = 1

        with patch('sys.argv', ['script.py', '--server-type', 'nginx']):
            result = main()
            assert result == 0

def test_main_with_vulnerabilities():
    with patch('scanners.nginx_scanner.NginxScanner') as mock_scanner:
        instance = mock_scanner.return_value
        instance.scan.return_value = [MagicMock()]
        instance.scanned_files_count = 1

        with patch('sys.argv', ['script.py', '--server-type', 'nginx']):
            result = main()
            assert result == 1

def test_nginx_scanner_find_config_files():
    with tempfile.TemporaryDirectory() as temp_dir:
        conf_file = os.path.join(temp_dir, 'nginx.conf')
        with open(conf_file, 'w') as f:
            f.write('server {}')

        scanner = NginxScanner(config_path=temp_dir)
        config_files = scanner.find_config_files()
        
        assert len(config_files) == 1
        assert config_files[0] == conf_file

def test_nginx_scanner_parse_config():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf') as temp_file:
        content = 'server { listen 80; }'
        temp_file.write(content)
        temp_file.flush()

        scanner = NginxScanner()
        parsed_content = scanner.parse_config(temp_file.name)
        assert parsed_content == content