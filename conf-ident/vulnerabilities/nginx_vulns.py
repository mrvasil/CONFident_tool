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
