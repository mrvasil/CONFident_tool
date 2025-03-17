import os
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    def __init__(self, config_path=None):
        self.config_path = config_path
        self.vulnerabilities = []
    
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
        
        for config_file in config_files:
            config_data = self.parse_config(config_file)
            self.check_vulnerabilities(config_data, config_file)
        
        return self.vulnerabilities 