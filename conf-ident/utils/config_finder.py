import os
import platform

class ConfigFinder:
    def __init__(self):
        self.os_type = platform.system()
    
    def find_nginx_configs(self, custom_path=None):
        if custom_path:
            return self._find_configs_in_path(custom_path, '.conf')
        
        default_paths = self._get_default_nginx_paths()
        return self._find_configs_in_multiple_paths(default_paths, '.conf')
    
    def find_apache_configs(self, custom_path=None):
        if custom_path:
            return self._find_configs_in_path(custom_path, '.conf')
        
        default_paths = self._get_default_apache_paths()
        return self._find_configs_in_multiple_paths(default_paths, '.conf')
    
    def _get_default_nginx_paths(self):
        if self.os_type == 'Linux':
            return [
                '/etc/nginx/',
                '/usr/local/nginx/conf/',
                '/usr/local/etc/nginx/'
            ]
        elif self.os_type == 'Darwin':  # macOS
            return [
                '/usr/local/etc/nginx/',
                '/opt/homebrew/etc/nginx/'
            ]
        elif self.os_type == 'Windows':
            return [
                'C:\\nginx\\conf\\',
                'C:\\Program Files\\nginx\\conf\\'
            ]
        return []
    
    def _get_default_apache_paths(self):
        if self.os_type == 'Linux':
            return [
                '/etc/apache2/',
                '/etc/httpd/',
                '/usr/local/apache2/conf/'
            ]
        elif self.os_type == 'Darwin':  # macOS
            return [
                '/usr/local/etc/apache2/',
                '/opt/homebrew/etc/httpd/'
            ]
        elif self.os_type == 'Windows':
            return [
                'C:\\Apache24\\conf\\',
                'C:\\Program Files\\Apache Group\\Apache2\\conf\\'
            ]
        return []
    
    def _find_configs_in_path(self, path, extension):
        config_files = []
        
        if os.path.isfile(path):
            if path.endswith(extension):
                config_files.append(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(extension):
                        config_files.append(os.path.join(root, file))
        
        return config_files
    
    def _find_configs_in_multiple_paths(self, paths, extension):
        config_files = []
        
        for path in paths:
            if os.path.exists(path):
                config_files.extend(self._find_configs_in_path(path, extension))
        
        return config_files
