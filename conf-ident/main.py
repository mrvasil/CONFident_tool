#!/usr/bin/env python3

# Copyright 2024 CONFident_tool
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import sys
from scanners.nginx_scanner import NginxScanner
from scanners.apache_scanner import ApacheScanner
from utils.report_generator import ReportGenerator

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Сканер уязвимостей в конфигурациях веб-серверов'
    )
    
    parser.add_argument(
        '--server-type', 
        choices=['nginx', 'apache'], 
        required=True,
        help='Тип веб-сервера для сканирования'
    )
    
    parser.add_argument(
        '--config-path',
        help='Путь к директории с конфигурационными файлами (если отличается от пути по умолчанию)'
    )
    
    parser.add_argument(
        '--output',
        default='console',
        choices=['console', 'json', 'html'],
        help='Формат вывода результатов'
    )
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    if args.server_type == 'nginx':
        scanner = NginxScanner(config_path=args.config_path)
    elif args.server_type == 'apache':
        scanner = ApacheScanner(config_path=args.config_path)
    else:
        print(f"Неподдерживаемый тип сервера: {args.server_type}")
        sys.exit(1)
    
    vulnerabilities = scanner.scan()
    
    report = ReportGenerator(
        vulnerabilities, 
        scanned_configs_count=scanner.scanned_files_count,
        output_format=args.output
    )
    report.generate()
    
    print(f"\nСканирование завершено. Найдено уязвимостей: {len(vulnerabilities)}")
    print(f"Просканировано конфигураций: {scanner.scanned_files_count}")
    
    return 1 if vulnerabilities else 0

if __name__ == "__main__":
    sys.exit(main())