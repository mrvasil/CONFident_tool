#!/usr/bin/env python3

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
import json
import tempfile
from datetime import datetime
from scanners.nginx_scanner import NginxScanner
from scanners.apache_scanner import ApacheScanner
from utils.report_generator import ReportGenerator


app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    server_type = request.form.get('server_type')
    config_path = request.form.get('config_path')
    output_format = request.form.get('output_format', 'html')
    
    if not server_type:
        flash('Необходимо выбрать тип сервера', 'error')
        return redirect(url_for('index'))
    
    if server_type == 'nginx':
        scanner = NginxScanner(config_path=config_path)
    elif server_type == 'apache':
        scanner = ApacheScanner(config_path=config_path)
    else:
        flash(f'Неподдерживаемый тип сервера: {server_type}', 'error')
        return redirect(url_for('index'))
    
    vulnerabilities = scanner.scan()
    
    if output_format == 'json':
        # Create JSON response
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerability_report_{timestamp}.json"
        report_path = os.path.join(os.getcwd(), "reports", filename)
        
        # Ensure reports directory exists
        os.makedirs(os.path.join(os.getcwd(), "reports"), exist_ok=True)
        
        report = ReportGenerator(vulnerabilities, output_format='json')
        report.generate(output_path=report_path)
        
        return send_file(report_path, as_attachment=True)
    
    elif output_format == 'html':
        # Create HTML response for displaying in browser
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerability_report_{timestamp}.html"
        report_path = os.path.join(os.getcwd(), "reports", filename)
        
        # Ensure reports directory exists
        os.makedirs(os.path.join(os.getcwd(), "reports"), exist_ok=True)
        
        report = ReportGenerator(vulnerabilities, output_format='html')
        report.generate(output_path=report_path)
        
        return render_template('results.html', 
                              vulnerabilities=vulnerabilities, 
                              count=len(vulnerabilities),
                              server_type=server_type,
                              config_path=config_path or "По умолчанию",
                              report_path=report_path)
    
    # Default to console output format
    return render_template('results.html', 
                          vulnerabilities=vulnerabilities, 
                          count=len(vulnerabilities),
                          server_type=server_type,
                          config_path=config_path or "По умолчанию",
                          report_path=None)

@app.route('/download/<path:filename>')
def download_report(filename):
    try:
        return send_file(filename, as_attachment=True)
    except Exception as e:
        flash(f'Ошибка при скачивании файла: {str(e)}', 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9696) 