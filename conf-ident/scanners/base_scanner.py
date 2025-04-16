import os
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    def __init__(self, config_path=None):
        self.config_path = config_path
        self.vulnerabilities = []
        self.scanned_files = set()
        self.scanned_files_count = 0
    
    @abstractmethod
    def find_config_files(self):
        pass
    
    @abstractmethod
    def parse_config(self, config_file):
        pass
    
    @abstractmethod
    def check_vulnerabilities(self, config_data, config_file):
        pass
    
    def scan(self):
        config_files = self.find_config_files()
        self.scanned_files = set(config_files)
        self.scanned_files_count = len(config_files)
        
        for config_file in config_files:
            config_data = self.parse_config(config_file)
            self.check_vulnerabilities(config_data, config_file)
        
        return self.vulnerabilities 