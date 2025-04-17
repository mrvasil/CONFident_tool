from vulnerabilities.base_vulnerability import Vulnerability

class DirectoryIndexingVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Directory Indexing Enabled",
            severity="medium",
            description="Включен просмотр содержимого директорий, что позволяет злоумышленникам просматривать содержимое каталогов на вашем сервере.",
            recommendation="Удалите 'Indexes' из директивы Options или используйте 'Options -Indexes' для явного отключения."
        )

class UnrestrictedCGIExecutionVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Unrestricted CGI Execution", 
            severity="high",
            description="Выполнение CGI-скриптов включено без надлежащих ограничений, что может позволить злоумышленникам выполнять вредоносный код на сервере.",
            recommendation="Ограничьте выполнение CGI определенными директориями и реализуйте надлежащий контроль доступа. Рассмотрите использование 'ScriptAlias' для CGI-директорий."
        )

class AllowAllHtaccessVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Unrestricted .htaccess Usage",
            severity="medium", 
            description="'AllowOverride All' позволяет файлам .htaccess переопределять любые директивы, что может привести к проблемам безопасности, если эти файлы будут скомпрометированы.",
            recommendation="Используйте 'AllowOverride None' или укажите только необходимые категории переопределения (например, 'AllowOverride AuthConfig Indexes')."
        )
