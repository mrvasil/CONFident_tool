#!/usr/bin/env python3

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, session
import json
import tempfile
from datetime import datetime
import uuid
from scanners.nginx_scanner import NginxScanner
from scanners.apache_scanner import ApacheScanner
from utils.report_generator import ReportGenerator
import pdfkit

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.urandom(24)
app.config['SCAN_HISTORY'] = []
app.config['MAX_HISTORY_SIZE'] = 10

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST', 'GET'])
def scan():
    if request.method == 'GET':
        server_type = request.args.get('server_type')
        config_path = request.args.get('config_path')
        output_format = request.args.get('output_format', 'html')
    else:
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
    
    vulnerable_files = set()
    for vuln in vulnerabilities:
        if hasattr(vuln, 'file_path') and vuln.file_path:
            vulnerable_files.add(vuln.file_path)
    
    safe_files = scanner.scanned_files - vulnerable_files
    safe_files_list = [os.path.basename(f) for f in safe_files]
    safe_files_count = len(safe_files)
   
    for vuln in vulnerabilities:
        vuln.title = vuln.name
        if hasattr(vuln, 'file_path') and vuln.file_path:
            vuln.display_file_path = os.path.basename(vuln.file_path)
            vuln.file_path = os.path.abspath(vuln.file_path)
    
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    high_count = len([v for v in vulnerabilities if v.severity == 'high'])
    medium_count = len([v for v in vulnerabilities if v.severity == 'medium'])
    low_count = len([v for v in vulnerabilities if v.severity == 'low'])
    
    scan_record = {
        'id': scan_id,
        'timestamp': timestamp,
        'datetime': datetime.now(),
        'server_type': server_type,
        'config_path': config_path or "По умолчанию",
        'vulnerabilities': vulnerabilities,
        'count': len(vulnerabilities),
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'scanned_configs_count': scanner.scanned_files_count
    }
    
    app.config['SCAN_HISTORY'].insert(0, scan_record)
    if len(app.config['SCAN_HISTORY']) > app.config['MAX_HISTORY_SIZE']:
        app.config['SCAN_HISTORY'].pop()
    
    session['last_scan_id'] = scan_id
    
    if output_format == 'json':
        filename = f"vulnerability_report_{timestamp}.json"
        report_path = os.path.join(os.getcwd(), "reports", filename)
        
        os.makedirs(os.path.join(os.getcwd(), "reports"), exist_ok=True)
        
        report = ReportGenerator(vulnerabilities, output_format='json')
        report.generate(output_path=report_path)
        
        return send_file(report_path, as_attachment=True)
    
    elif output_format == 'html':
        filename = f"vulnerability_report_{timestamp}.html"
        report_path = os.path.join(os.getcwd(), "reports", filename)
        
        os.makedirs(os.path.join(os.getcwd(), "reports"), exist_ok=True)
        
        report = ReportGenerator(vulnerabilities, output_format='html')
        report.generate(output_path=report_path)
        
        return render_template('results.html', 
                              vulnerabilities=vulnerabilities, 
                              count=len(vulnerabilities),
                              server_type=server_type,
                              config_path=config_path or "По умолчанию",
                              report_path=report_path,
                              scan_id=scan_id,
                              history=app.config['SCAN_HISTORY'],
                              datetime=datetime,
                              high_count=high_count,
                              medium_count=medium_count,
                              low_count=low_count,
                              scanned_configs_count=scanner.scanned_files_count,
                              safe_files=safe_files_list,
                              safe_files_count=safe_files_count)
    
    return render_template('results.html', 
                          vulnerabilities=vulnerabilities, 
                          count=len(vulnerabilities),
                          server_type=server_type,
                          config_path=config_path or "По умолчанию",
                          report_path=None,
                          scan_id=scan_id,
                          history=app.config['SCAN_HISTORY'],
                          datetime=datetime,
                          high_count=high_count,
                          medium_count=medium_count,
                          low_count=low_count,
                          scanned_configs_count=scanner.scanned_files_count)

@app.route('/download/<path:filename>')
def download_report(filename):
    try:
        return send_file(filename, as_attachment=True)
    except Exception as e:
        flash(f'Ошибка при скачивании файла: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/download_pdf_report')
def download_pdf_report():
    scan_id = session.get('last_scan_id')
    if not scan_id:
        flash('Отчет не найден', 'error')
        return redirect(url_for('index'))
    
    scan_data = None
    for scan in app.config['SCAN_HISTORY']:
        if scan['id'] == scan_id:
            scan_data = scan
            break
    
    if not scan_data:
        flash('Данные сканирования не найдены', 'error')
        return redirect(url_for('index'))
    
    for vuln in scan_data['vulnerabilities']:
        vuln.title = vuln.name
    
    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as temp_html:
        html_content = render_template(
            'pdf_report.html',
            vulnerabilities=scan_data['vulnerabilities'],
            count=scan_data['count'],
            server_type=scan_data['server_type'],
            config_path=scan_data['config_path'],
            timestamp=scan_data['timestamp'],
            high_count=scan_data['high_count'],
            medium_count=scan_data['medium_count'],
            low_count=scan_data['low_count'],
            scanned_configs_count=scan_data.get('scanned_configs_count', 0)
        )
        temp_html.write(html_content.encode('utf-8'))
        temp_html_path = temp_html.name
    
    pdf_filename = f"vulnerability_report_{scan_data['timestamp']}.pdf"
    pdf_path = os.path.join(os.getcwd(), "reports", pdf_filename)
    
    os.makedirs(os.path.join(os.getcwd(), "reports"), exist_ok=True)
    
    try:
        pdfkit.from_file(temp_html_path, pdf_path)
        os.unlink(temp_html_path)  # Remove temporary HTML file
        return send_file(pdf_path, as_attachment=True)
    except Exception as e:
        os.unlink(temp_html_path)  # Clean up even on error
        flash(f'Ошибка при создании PDF: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/history')
def history():
    total_high = sum(scan['high_count'] for scan in app.config['SCAN_HISTORY'])
    total_medium = sum(scan['medium_count'] for scan in app.config['SCAN_HISTORY'])
    total_low = sum(scan['low_count'] for scan in app.config['SCAN_HISTORY'])
    
    return render_template('history.html', 
                           history=app.config['SCAN_HISTORY'], 
                           datetime=datetime,
                           total_high=total_high,
                           total_medium=total_medium,
                           total_low=total_low)

@app.route('/view_scan/<scan_id>')
def view_scan(scan_id):
    scan_data = None
    for scan in app.config['SCAN_HISTORY']:
        if scan['id'] == scan_id:
            scan_data = scan
            break
    
    if not scan_data:
        flash('Данные сканирования не найдены', 'error')
        return redirect(url_for('history'))
    
    session['last_scan_id'] = scan_id
    
    for vuln in scan_data['vulnerabilities']:
        vuln.title = vuln.name
    
    return render_template('results.html',
                          vulnerabilities=scan_data['vulnerabilities'],
                          count=scan_data['count'],
                          server_type=scan_data['server_type'],
                          config_path=scan_data['config_path'],
                          report_path=None,
                          scan_id=scan_id,
                          history=app.config['SCAN_HISTORY'],
                          datetime=datetime,
                          high_count=scan_data['high_count'],
                          medium_count=scan_data['medium_count'],
                          low_count=scan_data['low_count'],
                          scanned_configs_count=scan_data.get('scanned_configs_count', 0))

@app.route('/delete_scan/<scan_id>')
def delete_scan(scan_id):
    for i, scan in enumerate(app.config['SCAN_HISTORY']):
        if scan['id'] == scan_id:
            app.config['SCAN_HISTORY'].pop(i)
            flash('Запись сканирования удалена', 'success')
            break
    
    return redirect(url_for('history'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9696) 