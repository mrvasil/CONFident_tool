from vulnerabilities.base_vulnerability import Vulnerability

class DirectoryListingVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Directory Listing Enabled",
            severity="medium",
            description="Включен просмотр содержимого директорий, что позволяет злоумышленникам просматривать содержимое каталогов на вашем сервере.",
            recommendation="Отключите просмотр директорий, удалив 'autoindex on' или установив 'autoindex off'."
        )

class NoRequestSizeLimitVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="No Request Size Limit",
            severity="medium",
            description="Не определен лимит размера запроса, что может позволить злоумышленникам выполнять атаки типа 'отказ в обслуживании' путем отправки больших запросов.",
            recommendation="Установите разумное ограничение размера запроса, используя директиву 'client_max_body_size'."
        )

class UnsafePHPExecutionVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Unsafe PHP Execution Configuration",
            severity="high",
            description="Конфигурация PHP уязвима для атак через загрузку файлов, что может привести к удаленному выполнению кода.",
            recommendation="Добавьте 'try_files $uri =404;' перед директивой fastcgi_pass для предотвращения выполнения несуществующих PHP файлов."
        )

class MIMESniffingVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="MIME Sniffing Enabled",
            severity="medium",
            description="Отсутствует защита от MIME-снифинга, что может позволить браузерам интерпретировать файлы не по их фактическому MIME-типу.",
            recommendation="Добавьте заголовок 'X-Content-Type-Options: nosniff' для предотвращения MIME-снифинга."
        )

class ClickjackingVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Clickjacking Protection Missing",
            severity="medium",
            description="Отсутствует защита от кликджекинга, что позволяет встраивать ваш сайт в iframe на других сайтах.",
            recommendation="Добавьте заголовок 'X-Frame-Options: SAMEORIGIN' для защиты от кликджекинга."
        )

class SSLTLSMisconfigurationVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="SSL/TLS Misconfiguration",
            severity="high",
            description="Обнаружены небезопасные настройки SSL/TLS, что может сделать соединение уязвимым для атак.",
            recommendation="Используйте только TLS 1.2+ и безопасные шифры, отключите устаревшие протоколы."
        )
