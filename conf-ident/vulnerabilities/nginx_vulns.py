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


class ServerTokensExposedVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Server Version Disclosure",
            severity="low",
            description="Версия сервера раскрывается в HTTP-заголовках, что помогает злоумышленникам подбирать эксплойты под конкретную версию.",
            recommendation="Добавьте 'server_tokens off;' в блок http для скрытия версии Nginx."
        )


class XSSProtectionMissingVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="XSS Protection Header Missing",
            severity="medium",
            description="Отсутствует заголовок X-XSS-Protection, что снижает защиту от отражённых XSS-атак в старых браузерах.",
            recommendation="Добавьте 'add_header X-XSS-Protection \"1; mode=block\";' в конфигурацию сервера."
        )


class HSTSMissingVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="HSTS Not Configured",
            severity="high",
            description="HTTP Strict Transport Security не настроен. Пользователи могут быть перенаправлены на HTTP-версию сайта, что делает возможными атаки типа SSL stripping.",
            recommendation="Добавьте 'add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;' для принудительного использования HTTPS."
        )


class ContentSecurityPolicyMissingVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Content-Security-Policy Missing",
            severity="medium",
            description="Отсутствует заголовок Content-Security-Policy, что делает сайт уязвимым для XSS-атак и инъекций контента.",
            recommendation="Добавьте заголовок 'Content-Security-Policy' с подходящей политикой, например: \"default-src 'self'; script-src 'self'\"."
        )


class ReferrerPolicyMissingVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Referrer-Policy Not Set",
            severity="low",
            description="Отсутствует заголовок Referrer-Policy. Браузер может передавать полный URL в заголовке Referer при переходе на внешние сайты, раскрывая конфиденциальные данные из URL.",
            recommendation="Добавьте 'add_header Referrer-Policy \"strict-origin-when-cross-origin\";' в конфигурацию."
        )


class PermissionsPolicyMissingVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Permissions-Policy Not Set",
            severity="low",
            description="Отсутствует заголовок Permissions-Policy (ранее Feature-Policy). Сторонние скрипты могут получить доступ к камере, микрофону, геолокации и другим API браузера.",
            recommendation="Добавьте 'add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\";' для ограничения доступа к API."
        )
