using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using InfoSecContour.Models;

namespace InfoSecContour.Services;

public class SecurityApplication
{
    private readonly string _dataDirectory;
    private readonly UserStore _userStore;
    private readonly AuditService _auditService;
    private readonly PasswordService _passwordService;
    private readonly DpapiService _dpapiService;
    private readonly CertificateValidationService _certificateService;
    private UserAccount? _currentUser;

    public SecurityApplication()
    {
        _dataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "InfoSecContour");
        Directory.CreateDirectory(_dataDirectory);

        _userStore = new UserStore(_dataDirectory);
        _auditService = new AuditService(_dataDirectory);
        _passwordService = new PasswordService();
        _dpapiService = new DpapiService();
        _certificateService = new CertificateValidationService();
    }

    public void Run()
    {
        PrintHeader();

        try
        {
            _userStore.Initialize();
        }
        catch (Exception exception)
        {
            Console.WriteLine($"Не удалось открыть базу учетных записей: {exception.Message}");
            return;
        }

        if (!Authenticate())
        {
            Console.WriteLine("Вход не выполнен. Программа завершена.");
            return;
        }

        _auditService.Write(_currentUser!.Username, "LOGIN", "SUCCESS");

        bool running = true;
        while (running)
        {
            PrintMenu();
            Console.Write("Выберите действие: ");
            string choice = (Console.ReadLine() ?? string.Empty).Trim();

            switch (choice)
            {
                case "1":
                    RunPasswordHash();
                    break;
                case "2":
                    RunPasswordVerification();
                    break;
                case "3":
                    RunDpapiProtection();
                    break;
                case "4":
                    RunDpapiDecryption();
                    break;
                case "5":
                    RunCertificateValidation();
                    break;
                case "6":
                    ManageUsers();
                    break;
                case "7":
                    ShowAuditLog();
                    break;
                case "0":
                    _auditService.Write(_currentUser!.Username, "LOGOUT", "SUCCESS");
                    running = false;
                    break;
                default:
                    Console.WriteLine("Неизвестная команда.");
                    break;
            }

            if (running)
            {
                Console.WriteLine("\nНажмите Enter, чтобы продолжить...");
                Console.ReadLine();
            }
        }

        Console.WriteLine("Работа программы завершена.");
    }

    private static void PrintHeader()
    {
        Console.WriteLine("============================================");
        Console.WriteLine("     КОНТУР ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ");
        Console.WriteLine("============================================");
        Console.WriteLine("DPAPI | BCrypt | X.509 | RBAC");
        Console.WriteLine();
    }

    private bool Authenticate()
    {
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            Console.WriteLine("\nВход в систему");
            Console.Write("Имя пользователя: ");
            string username = (Console.ReadLine() ?? string.Empty).Trim();
            string password = ConsoleInput.ReadPassword("Пароль: ");

            UserAccount? user = _userStore.Find(username);
            if (user != null && _userStore.VerifyPassword(user, password))
            {
                _currentUser = user;
                Console.WriteLine($"\nДобро пожаловать, {user.Username}. Роль: {user.Role}");
                return true;
            }

            _auditService.Write(username, "LOGIN", "FAILED");
            Console.WriteLine($"Неверное имя пользователя или пароль. Осталось попыток: {3 - attempt}");
        }

        return false;
    }

    private void PrintMenu()
    {
        Console.Clear();
        Console.WriteLine($"Пользователь: {_currentUser!.Username} | Роль: {_currentUser.Role}");
        Console.WriteLine("--------------------------------------------");
        PrintMenuItem("1", "Создать BCrypt-хеш пароля", Permission.HashPassword);
        PrintMenuItem("2", "Проверить пароль по BCrypt-хешу", Permission.VerifyPassword);
        PrintMenuItem("3", "Зашифровать секрет через DPAPI", Permission.ProtectSecret);
        PrintMenuItem("4", "Расшифровать секрет через DPAPI", Permission.UnprotectSecret);
        PrintMenuItem("5", "Проверить X.509 сертификат", Permission.ValidateCertificate);
        PrintMenuItem("6", "Управление пользователями", Permission.ManageUsers);
        PrintMenuItem("7", "Просмотр журнала действий", Permission.ViewAuditLog);
        Console.WriteLine("0. Выход");
        Console.WriteLine("--------------------------------------------");
    }

    private void PrintMenuItem(string number, string title, Permission permission)
    {
        string access = AuthorizationService.HasPermission(_currentUser!.Role, permission)
            ? string.Empty
            : " [нет доступа]";
        Console.WriteLine($"{number}. {title}{access}");
    }

    private bool CheckPermission(Permission permission, string action)
    {
        bool allowed = AuthorizationService.HasPermission(_currentUser!.Role, permission);
        _auditService.Write(_currentUser.Username, action, allowed ? "ALLOWED" : "DENIED");

        if (!allowed)
        {
            Console.WriteLine("Доступ запрещен. Недостаточно прав для этой операции.");
        }

        return allowed;
    }

    private void RunPasswordHash()
    {
        if (!CheckPermission(Permission.HashPassword, "BCrypt_HASH"))
        {
            return;
        }

        string password = ConsoleInput.ReadPassword("Введите пароль для хеширования: ");

        try
        {
            string hash = _passwordService.CreateHash(password);
            Console.WriteLine("\nBCrypt-хеш:");
            Console.WriteLine(hash);
            _auditService.Write(_currentUser!.Username, "BCrypt_HASH", "SUCCESS");
        }
        catch (Exception exception)
        {
            Console.WriteLine($"Ошибка: {exception.Message}");
            _auditService.Write(_currentUser!.Username, "BCrypt_HASH", "FAILED");
        }
    }

    private void RunPasswordVerification()
    {
        if (!CheckPermission(Permission.VerifyPassword, "BCrypt_VERIFY"))
        {
            return;
        }

        string password = ConsoleInput.ReadPassword("Введите исходный пароль: ");
        string hash = ConsoleInput.ReadRequired("Вставьте BCrypt-хеш: ");

        try
        {
            bool valid = _passwordService.Verify(password, hash);
            Console.WriteLine(valid ? "Пароль совпадает с хешем." : "Пароль не совпадает с хешем.");
            _auditService.Write(_currentUser!.Username, "BCrypt_VERIFY", valid ? "MATCH" : "NO_MATCH");
        }
        catch (Exception exception)
        {
            Console.WriteLine($"Ошибка: {exception.Message}");
            _auditService.Write(_currentUser!.Username, "BCrypt_VERIFY", "FAILED");
        }
    }

    private void RunDpapiProtection()
    {
        if (!CheckPermission(Permission.ProtectSecret, "DPAPI_PROTECT"))
        {
            return;
        }

        string secret = ConsoleInput.ReadPassword("Введите секрет для шифрования: ");
        string filePath = Path.Combine(_dataDirectory, "protected-secret.bin");

        try
        {
            _dpapiService.ProtectToFile(secret, filePath);
            Console.WriteLine($"Секрет зашифрован и сохранен в: {filePath}");
            _auditService.Write(_currentUser!.Username, "DPAPI_PROTECT", "SUCCESS");
        }
        catch (PlatformNotSupportedException exception)
        {
            Console.WriteLine(exception.Message);
            _auditService.Write(_currentUser!.Username, "DPAPI_PROTECT", "UNSUPPORTED_PLATFORM");
        }
        catch (CryptographicException)
        {
            Console.WriteLine("Не удалось зашифровать данные средствами DPAPI.");
            _auditService.Write(_currentUser!.Username, "DPAPI_PROTECT", "FAILED");
        }
        catch (Exception exception)
        {
            Console.WriteLine($"Ошибка: {exception.Message}");
            _auditService.Write(_currentUser!.Username, "DPAPI_PROTECT", "FAILED");
        }
    }

    private void RunDpapiDecryption()
    {
        if (!CheckPermission(Permission.UnprotectSecret, "DPAPI_UNPROTECT"))
        {
            return;
        }

        string filePath = Path.Combine(_dataDirectory, "protected-secret.bin");

        try
        {
            string secret = _dpapiService.UnprotectFromFile(filePath);
            Console.WriteLine("Расшифрованный секрет:");
            Console.WriteLine(secret);
            _auditService.Write(_currentUser!.Username, "DPAPI_UNPROTECT", "SUCCESS");
        }
        catch (PlatformNotSupportedException exception)
        {
            Console.WriteLine(exception.Message);
            _auditService.Write(_currentUser!.Username, "DPAPI_UNPROTECT", "UNSUPPORTED_PLATFORM");
        }
        catch (FileNotFoundException exception)
        {
            Console.WriteLine(exception.Message);
            _auditService.Write(_currentUser!.Username, "DPAPI_UNPROTECT", "NO_FILE");
        }
        catch (CryptographicException)
        {
            Console.WriteLine("Не удалось расшифровать данные. Возможно, они повреждены или зашифрованы другим профилем Windows.");
            _auditService.Write(_currentUser!.Username, "DPAPI_UNPROTECT", "FAILED");
        }
        catch (Exception exception)
        {
            Console.WriteLine($"Ошибка: {exception.Message}");
            _auditService.Write(_currentUser!.Username, "DPAPI_UNPROTECT", "FAILED");
        }
    }

    private void RunCertificateValidation()
    {
        if (!CheckPermission(Permission.ValidateCertificate, "X509_VALIDATE"))
        {
            return;
        }

        string path = ConsoleInput.ReadRequired("Путь к сертификату (.cer/.crt/.pem/.pfx/.p12): ");
        string fullPath = Path.GetFullPath(path);
        string? pfxPassword = null;
        X509ContentType contentType;

        try
        {
            contentType = System.Security.Cryptography.X509Certificates.X509Certificate2.GetCertContentType(fullPath);
        }
        catch (Exception exception)
        {
            Console.WriteLine($"Не удалось определить формат сертификата: {exception.Message}");
            _auditService.Write(_currentUser!.Username, "X509_VALIDATE", "INVALID_FILE");
            return;
        }

        if (contentType == X509ContentType.Pkcs12)
        {
            pfxPassword = ConsoleInput.ReadPassword("Пароль PFX/P12 (Enter, если отсутствует): ");
        }

        Console.Write("Проверить отзыв сертификата через интернет? (д/н, по умолчанию н): ");
        string revocationAnswer = (Console.ReadLine() ?? string.Empty).Trim();
        bool checkRevocationOnline = revocationAnswer.Equals("д", StringComparison.OrdinalIgnoreCase) ||
                                     revocationAnswer.Equals("y", StringComparison.OrdinalIgnoreCase);

        try
        {
            CertificateCheckResult result = _certificateService.ValidateFile(fullPath, pfxPassword, checkRevocationOnline);
            PrintCertificateResult(result, checkRevocationOnline);
            _auditService.Write(_currentUser!.Username, "X509_VALIDATE", result.IsValid ? "VALID" : "INVALID");
        }
        catch (Exception exception)
        {
            Console.WriteLine($"Ошибка проверки сертификата: {exception.Message}");
            _auditService.Write(_currentUser!.Username, "X509_VALIDATE", "FAILED");
        }
    }

    private static void PrintCertificateResult(CertificateCheckResult result, bool revocationChecked)
    {
        Console.WriteLine("\nИнформация о сертификате");
        Console.WriteLine($"Subject: {result.Subject}");
        Console.WriteLine($"Issuer: {result.Issuer}");
        Console.WriteLine($"Thumbprint: {result.Thumbprint}");
        Console.WriteLine($"Действителен с: {result.NotBeforeUtc:u}");
        Console.WriteLine($"Действителен до: {result.NotAfterUtc:u}");
        Console.WriteLine($"Проверка отзыва: {(revocationChecked ? "Online" : "не выполнялась")}");

        Console.WriteLine("\nЦепочка сертификатов:");
        foreach (string subject in result.ChainSubjects)
        {
            Console.WriteLine($" - {subject}");
        }

        Console.WriteLine("\nРезультат проверки:");
        foreach (string status in result.ChainStatuses)
        {
            Console.WriteLine($" - {status}");
        }

        Console.WriteLine(result.IsValid
            ? "\nСертификат прошел проверку цепочки доверия."
            : "\nСертификат НЕ прошел проверку цепочки доверия.");
    }

    private void ManageUsers()
    {
        if (!CheckPermission(Permission.ManageUsers, "USER_MANAGEMENT"))
        {
            return;
        }

        Console.WriteLine("\nУчетные записи:");
        foreach (UserAccount user in _userStore.GetAll())
        {
            Console.WriteLine($"- {user.Username} | {user.Role} | создана {user.CreatedAtUtc:u}");
        }

        Console.WriteLine("\nСоздать нового пользователя? (д/н): ");
        string answer = (Console.ReadLine() ?? string.Empty).Trim();
        if (!answer.Equals("д", StringComparison.OrdinalIgnoreCase) &&
            !answer.Equals("y", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        string username = ConsoleInput.ReadRequired("Имя нового пользователя: ");
        string password = UserStore.ReadNewPassword();

        Console.WriteLine("Роль: 1 — SecurityOperator, 2 — Auditor, 3 — Administrator");
        Console.Write("Выберите роль: ");
        string roleChoice = (Console.ReadLine() ?? string.Empty).Trim();

        UserRole role;
        switch (roleChoice)
        {
            case "1":
                role = UserRole.SecurityOperator;
                break;
            case "2":
                role = UserRole.Auditor;
                break;
            case "3":
                role = UserRole.Administrator;
                break;
            default:
                Console.WriteLine("Неизвестная роль. Пользователь не создан.");
                _auditService.Write(_currentUser!.Username, "USER_CREATE", "INVALID_ROLE");
                return;
        }

        bool created = _userStore.AddUser(username, password, role);
        Console.WriteLine(created ? "Пользователь создан." : "Пользователь с таким именем уже существует.");
        _auditService.Write(_currentUser!.Username, "USER_CREATE", created ? "SUCCESS" : "DUPLICATE");
    }

    private void ShowAuditLog()
    {
        if (!CheckPermission(Permission.ViewAuditLog, "AUDIT_VIEW"))
        {
            return;
        }

        _auditService.ShowLastEntries(50);
        _auditService.Write(_currentUser!.Username, "AUDIT_VIEW", "SUCCESS");
    }
}
