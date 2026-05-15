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


class ServerSignatureExposedVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Server Signature Exposed",
            severity="low",
            description="Подпись сервера включена, что раскрывает версию Apache и модули в страницах ошибок и листингах директорий.",
            recommendation="Добавьте 'ServerSignature Off' и 'ServerTokens Prod' в конфигурацию для скрытия информации о сервере."
        )


class TraceMethodEnabledVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="HTTP TRACE Method Enabled",
            severity="medium",
            description="Метод TRACE включен, что может быть использован для Cross-Site Tracing (XST) атак и кражи учётных данных.",
            recommendation="Добавьте 'TraceEnable Off' в конфигурацию для отключения метода TRACE."
        )


class ServerTokensFullVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Server Tokens Full Disclosure",
            severity="low",
            description="ServerTokens не ограничен, сервер раскрывает полную информацию о версии ОС и модулях в HTTP-заголовках.",
            recommendation="Установите 'ServerTokens Prod' для минимизации раскрываемой информации."
        )


class SSIEnabledVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Server-Side Includes Enabled",
            severity="medium",
            description="Server-Side Includes (SSI) включены с возможностью выполнения команд, что может привести к удалённому выполнению кода.",
            recommendation="Удалите 'Includes' из Options или используйте 'IncludesNOEXEC' для запрета выполнения команд."
        )


class SymlinksFollowedVulnerability(Vulnerability):
    def __init__(self):
        super().__init__(
            name="Symbolic Links Followed",
            severity="medium",
            description="Сервер следует символическим ссылкам без проверки владельца, что может позволить доступ к файлам за пределами корневой директории.",
            recommendation="Замените 'FollowSymLinks' на 'SymLinksIfOwnerMatch' или удалите эту опцию."
        )
