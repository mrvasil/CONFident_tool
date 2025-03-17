import logging
import os
from datetime import datetime

class Logger:
    def __init__(self, log_level=logging.INFO, log_file=None):
        self.logger = logging.getLogger('conf-ident')
        self.logger.setLevel(log_level)
        
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        
        self.logger.propagate = False
    
    def get_logger(self):
        return self.logger

def setup_logger(log_level=logging.INFO, log_to_file=False):
    log_file = None
    
    if log_to_file:
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(log_dir, f'conf-ident_{timestamp}.log')
    
    logger_instance = Logger(log_level=log_level, log_file=log_file)
    return logger_instance.get_logger()
