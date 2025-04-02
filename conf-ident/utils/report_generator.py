import json
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, vulnerabilities, output_format='console'):
        self.vulnerabilities = vulnerabilities
        self.output_format = output_format
    
    def generate(self):
        if self.output_format == 'console':
            self._generate_console_report()
        elif self.output_format == 'json':
            self._generate_json_report()
        elif self.output_format == 'html':
            self._generate_html_report()
    
    def _generate_console_report(self):
        if not self.vulnerabilities:
            print("\n✅ No vulnerabilities found!")
            return
        
        print("\n🔍 Vulnerability Scan Results:")
        print("=" * 80)
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            severity_color = self._get_severity_color(vuln.severity)
            print(f"{i}. {severity_color}{vuln.name} (Severity: {vuln.severity.upper()})\033[0m")
            print(f"   Description: {vuln.description}")
            print(f"   Recommendation: {vuln.recommendation}")
            
            if vuln.cve_id:
                print(f"   CVE ID: {vuln.cve_id}")
            
            print("   Affected files:")
            for file_path in vuln.affected_files:
                print(f"   - {file_path}")
                if file_path in vuln.matched_lines and vuln.matched_lines[file_path]:
                    print(f"     Lines: {', '.join(map(str, vuln.matched_lines[file_path]))}")
            
            print("-" * 80)
    
    def _generate_json_report(self):
        report = {
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities_count': len(self.vulnerabilities),
            'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities]
        }
        
        filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nJSON report saved to {filename}")
    
    def _generate_html_report(self):
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .vulnerability {{ margin-bottom: 20px; border: 1px solid #ddd; padding: 10px; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #d9534f; }}
                .high {{ border-left: 5px solid #f0ad4e; }}
                .medium {{ border-left: 5px solid #5bc0de; }}
                .low {{ border-left: 5px solid #5cb85c; }}
                .file {{ margin-left: 20px; }}
                .lines {{ font-family: monospace; color: #666; }}
            </style>
        </head>
        <body>
            <h1>Vulnerability Scan Report</h1>
            <p>Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total vulnerabilities found: {len(self.vulnerabilities)}</p>
            
            <div class="vulnerabilities">
        """
        
        for vuln in self.vulnerabilities:
            html_content += f"""
                <div class="vulnerability {vuln.severity.lower()}">
                    <h2>{vuln.name} (Severity: {vuln.severity.upper()})</h2>
                    <p><strong>Description:</strong> {vuln.description}</p>
                    <p><strong>Recommendation:</strong> {vuln.recommendation}</p>
            """
            
            if vuln.cve_id:
                html_content += f"<p><strong>CVE ID:</strong> {vuln.cve_id}</p>"
            
            html_content += "<p><strong>Affected files:</strong></p>"
            
            for file_path in vuln.affected_files:
                html_content += f'<div class="file">{file_path}'
                
                if file_path in vuln.matched_lines and vuln.matched_lines[file_path]:
                    line_numbers = ', '.join(map(str, vuln.matched_lines[file_path]))
                    html_content += f'<div class="lines">Lines: {line_numbers}</div>'
                
                html_content += '</div>'
            
            html_content += "</div>"
        
        html_content += """
            </div>
        </body>
        </html>
        """
        
        filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w') as f:
            f.write(html_content)
        
        print(f"\nHTML report saved to {filename}")
    
    def _get_severity_color(self, severity):
        colors = {
            'critical': '\033[91m',  
            'high': '\033[93m',      
            'medium': '\033[94m',    
            'low': '\033[92m'        
        }
        return colors.get(severity.lower(), '\033[0m')
