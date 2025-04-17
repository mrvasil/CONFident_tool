import pandas as pd

vulnerabilities_data = {
    '№': range(1, 19),
    'Тип уязвимости': [
        'Directory Listing',
        'HTTP Response Splitting',
        'Unrestricted CGI',
        'Path Traversal',
        'No Request Size Limit',
        'SSRF',
        'SSL/TLS Misconfiguration',
        'Server Info Disclosure',
        'MIME Sniffing',
        'Clickjacking',
        'CORS Misconfiguration',
        'HTTP Splitting',
        'Origin/Referer Validation Issues',
        'Add Header Redefinition',
        'Host Header Spoofing',
        'Valid Referers None',
        'Multiline Response Headers',
        'Alias Path Traversal'
    ],
    'Описание': [
        'Включенный листинг директорий позволяет просматривать содержимое папок сервера',
        'Возможность внедрения дополнительных заголовков HTTP через манипуляцию с CRLF',
        'Неограниченное выполнение CGI скриптов без должной проверки',
        'Возможность доступа к файлам за пределами корневой директории веб-сервера',
        'Отсутствие ограничений на размер запросов может привести к DoS атакам',
        'Server-Side Request Forgery - возможность выполнения запросов от имени сервера',
        'Небезопасные настройки SSL/TLS протоколов и шифров',
        'Раскрытие информации о версии и типе веб-сервера',
        'Возможность подмены MIME типов в ответах сервера',
        'Отсутствие защиты от встраивания сайта в iframe',
        'Неправильная настройка Cross-Origin Resource Sharing',
        'Возможность внедрения дополнительных HTTP заголовков через манипуляции с разделителями строк',
        'Недостаточная валидация заголовков Origin/Referer может привести к CSRF атакам',
        'Переопределение заголовков ответа директивой add_header может привести к удалению важных защитных заголовков',
        'Подделка заголовка Host в запросе может привести к обходу защиты и атакам',
        'Использование none в valid_referers позволяет обойти защиту от подделки реферера',
        'Многострочные заголовки ответа могут использоваться для инъекций и обхода защиты',
        'Некорректная настройка директивы alias может привести к обходу ограничений доступа к файлам'
    ],
    'Веб-сервер': [
        'Nginx, Apache',
        'Nginx, Apache',
        'Apache',
        'Nginx, Apache',
        'Nginx, Apache',
        'Nginx, Apache',
        'Nginx, Apache',
        'Nginx, Apache',
        'Nginx, Apache',
        'Nginx, Apache',
        'Nginx, Apache',
        'Nginx, Apache',
        'Nginx',
        'Nginx',
        'Nginx',
        'Nginx',
        'Nginx',
        'Nginx'
    ],
    'Рекомендация': [
        'Отключить autoindex в Nginx или Options -Indexes в Apache',
        'Включить валидацию заголовков и экранирование спецсимволов',
        'Ограничить выполнение CGI скриптов, использовать suEXEC, установить корректные права доступа',
        'Настроить корректные alias и root директивы, включить символические ссылки только где необходимо',
        'Установить лимиты client_max_body_size, LimitRequestBody и другие ограничения',
        'Настроить валидацию URL, использовать белые списки разрешенных адресов',
        'Использовать только TLS 1.2+, настроить безопасные шифры',
        'Отключить server_tokens в Nginx или ServerTokens Prod в Apache',
        'Добавить заголовок X-Content-Type-Options: nosniff',
        'Добавить заголовок X-Frame-Options: SAMEORIGIN',
        'Настроить корректные CORS заголовки с явным указанием разрешенных источников',
        'Использовать валидацию и санитизацию входных данных, особенно заголовков',
        'Реализовать строгую проверку Origin/Referer с учетом всех доверенных источников',
        'Использовать директиву add_header только в основном контексте http или server',
        'Настроить валидацию заголовка Host и использовать server_name для определения виртуальных хостов',
        'Избегать использования none в valid_referers, явно указывать разрешенные источники',
        'Обеспечить корректную обработку и валидацию многострочных заголовков',
        'Тщательно проверять конфигурацию alias и использовать root где возможно'
    ],
    'Пример': [
        'autoindex off; # Nginx\nOptions -Indexes # Apache',
        'proxy_set_header Accept-Encoding "";\nproxy_set_header Accept-Language "";',
        '<Directory "/var/www/cgi-bin">\n    Options +ExecCGI\n    AddHandler cgi-script .cgi\n</Directory>',
        'disable_symlinks on; # Nginx\nOptions -FollowSymLinks # Apache',
        'client_max_body_size 10m; # Nginx\nLimitRequestBody 10485760 # Apache',
        'proxy_pass $validated_url; # После проверки URL',
        'ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5;',
        'server_tokens off; # Nginx\nServerTokens Prod # Apache',
        'add_header X-Content-Type-Options nosniff;',
        'add_header X-Frame-Options SAMEORIGIN;',
        'add_header Access-Control-Allow-Origin https://trusted-site.com;',
        'proxy_set_header Accept-Encoding "";\nproxy_set_header Accept-Language "";',
        'if ($http_origin ~ "^https?://([^/]+\\.)?example\\.com$") { set $origin_valid 1; }',
        'add_header X-Frame-Options DENY always;\nadd_header X-XSS-Protection "1; mode=block" always;',
        'server_name example.com;\nif ($host != $server_name) { return 444; }',
        'valid_referers server_names *.example.com example.* www.example.org/;',
        'proxy_set_header Accept-Encoding "";\nproxy_set_header Accept-Language "";',
        'location /files { alias /path/to/files/; }'
    ]
}

df = pd.DataFrame(vulnerabilities_data)

with pd.ExcelWriter('web_server_vulnerabilities.xlsx', engine='xlsxwriter') as writer:
    df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
    
    workbook = writer.book
    worksheet = writer.sheets['Vulnerabilities']
    
    worksheet.set_column('A:A', 5)  # Column width for №
    worksheet.set_column('B:B', 25)  # Column width for Тип уязвимости
    worksheet.set_column('C:C', 50)  # Column width for Описание
    worksheet.set_column('D:D', 15)  # Column width for Веб-сервер
    worksheet.set_column('E:E', 60)  # Column width for Рекомендация
    worksheet.set_column('F:F', 50)  # Column width for Пример
    
    header_format = workbook.add_format({
        'bold': True,
        'text_wrap': True,
        'valign': 'vcenter',
        'fg_color': '#D7E4BC',
        'border': 1
    })
    
    cell_format = workbook.add_format({
        'text_wrap': True,
        'valign': 'vcenter',
        'border': 1
    })
    
    for col_num, value in enumerate(df.columns.values):
        worksheet.write(0, col_num, value, header_format)
    
    for row in range(len(df)):
        for col in range(len(df.columns)):
            worksheet.write(row + 1, col, df.iloc[row, col], cell_format)

print("Таблица успешно сохранена в файл 'web_server_vulnerabilities.xlsx'")