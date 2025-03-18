# CONFident_tool

## Сканер уязвимостей в конфигурациях веб-серверов

CONFident_tool — это инструмент для автоматизированного анализа конфигурационных файлов веб-серверов (Nginx, Apache) на предмет ошибок настройки и потенциальных уязвимостей.

### Возможности

- Анализ конфигураций Nginx и Apache
- Обнаружение распространенных уязвимостей в настройках
- Формирование подробных отчетов с рекомендациями
- Поддержка различных форматов вывода (консоль, JSON, HTML)
- Возможность указания пользовательского пути к конфигурационным файлам

### Установка

```bash
git clone https://github.com/username/CONFident_tool.git
cd CONFident_tool
pip install -r requirements.txt
```

### Использование

```bash
conf-ident/main.py --server-type <nginx/apache> --config-path /path/to/configs --output <console/json/html>
```