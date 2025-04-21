from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.units import inch

class PDFReportGenerator:
    def __init__(self, scan_data):
        self.scan_data = scan_data
        self.styles = getSampleStyleSheet()
        self.story = []
        
    def generate(self, output_path):
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        self._add_title()
        self._add_info()
        self._add_statistics()
        self._add_vulnerabilities()
        
        doc.build(self.story)
    
    def _add_title(self):
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        
        self.story.append(Paragraph("Отчет о сканировании уязвимостей", title_style))
        self.story.append(Spacer(1, 12))
    
    def _add_info(self):
        info_style = ParagraphStyle(
            'Info',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=6
        )
        
        self.story.append(Paragraph(f"Дата сканирования: {self.scan_data['timestamp']}", info_style))
        self.story.append(Paragraph(f"Тип сервера: {self.scan_data['server_type']}", info_style))
        self.story.append(Paragraph(f"Путь конфигурации: {self.scan_data['config_path']}", info_style))
        self.story.append(Spacer(1, 12))
    
    def _add_statistics(self):
        stats_data = [
            ['Уровень', 'Количество'],
            ['High', str(self.scan_data['high_count'])],
            ['Medium', str(self.scan_data['medium_count'])],
            ['Low', str(self.scan_data['low_count'])],
            ['Всего', str(self.scan_data['count'])]
        ]
        
        stats_table = Table(stats_data, colWidths=[200, 100])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        self.story.append(stats_table)
        self.story.append(Spacer(1, 20))
    
    def _add_vulnerabilities(self):
        if self.scan_data['vulnerabilities']:
            vuln_style = ParagraphStyle(
                'VulnTitle',
                parent=self.styles['Heading2'],
                fontSize=16,
                spaceAfter=10
            )
            
            info_style = ParagraphStyle(
                'Info',
                parent=self.styles['Normal'],
                fontSize=12,
                spaceAfter=6
            )
            
            self.story.append(Paragraph("Найденные уязвимости:", vuln_style))
            self.story.append(Spacer(1, 12))
            
            for vuln in self.scan_data['vulnerabilities']:
                self.story.append(Paragraph(f"Название: {vuln.name}", self.styles['Heading3']))
                self.story.append(Paragraph(f"Уровень: {vuln.severity.upper()}", info_style))
                self.story.append(Paragraph(f"Описание: {vuln.description}", info_style))
                self.story.append(Paragraph(f"Рекомендации: {vuln.recommendation}", info_style))
                if hasattr(vuln, 'file_path') and vuln.file_path:
                    self.story.append(Paragraph(f"Файл: {vuln.file_path}", info_style))
                self.story.append(Spacer(1, 12))
        else:
            self.story.append(Paragraph("Уязвимости не обнаружены", self.styles['Heading2'])) 