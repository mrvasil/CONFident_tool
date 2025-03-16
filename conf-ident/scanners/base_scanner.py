from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseScanner(ABC):
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.vulnerabilities = []
    
    @abstractmethod
    def find_config_files(self) -> List[str]:
        pass
    
    @abstractmethod
    def parse_config(self, config_file: str) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def check_vulnerabilities(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        pass
    
    def scan(self) -> List[Dict[str, Any]]:
        config_files = self.find_config_files()
        
        if not config_files:
            print("Конфигурационные файлы не найдены")
            return []
        
        for config_file in config_files:
            print(f"Сканирование файла: {config_file}")
            config = self.parse_config(config_file)
            vulns = self.check_vulnerabilities(config)
            for vuln in vulns:
                vuln['file'] = config_file
                self.vulnerabilities.append(vuln)
        
        return self.vulnerabilities