using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using InfoSecContour.Models;

namespace InfoSecContour.Services;

public class UserStore
{
    private readonly string _filePath;
    private readonly JsonSerializerOptions _jsonOptions;
    private List<UserAccount> _users = new();

    public UserStore(string dataDirectory)
    {
        _filePath = Path.Combine(dataDirectory, "users.json");
        _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true
        };
        _jsonOptions.Converters.Add(new JsonStringEnumConverter());
    }

    public void Initialize()
    {
        if (!File.Exists(_filePath))
        {
            _users = new List<UserAccount>();
            Save();
        }
        else
        {
            string json = File.ReadAllText(_filePath);
            _users = JsonSerializer.Deserialize<List<UserAccount>>(json, _jsonOptions) ?? new List<UserAccount>();
        }

        if (_users.Count == 0)
        {
            CreateFirstAdministrator();
        }
    }

    public UserAccount? Find(string username)
    {
        return _users.FirstOrDefault(user =>
            string.Equals(user.Username, username, StringComparison.OrdinalIgnoreCase));
    }

    public bool AddUser(string username, string password, UserRole role)
    {
        if (Find(username) != null)
        {
            return false;
        }

        _users.Add(new UserAccount
        {
            Username = username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12),
            Role = role,
            CreatedAtUtc = DateTime.UtcNow
        });

        Save();
        return true;
    }

    public IReadOnlyList<UserAccount> GetAll()
    {
        return _users.AsReadOnly();
    }

    public bool VerifyPassword(UserAccount user, string password)
    {
        return BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
    }

    private void CreateFirstAdministrator()
    {
        Console.WriteLine("Первичная настройка системы безопасности");
        Console.WriteLine("Создайте учетную запись администратора.");

        string username = ConsoleInput.ReadRequired("Имя администратора: ");
        string password = ReadNewPassword();

        _users.Add(new UserAccount
        {
            Username = username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12),
            Role = UserRole.Administrator,
            CreatedAtUtc = DateTime.UtcNow
        });

        Save();
        Console.WriteLine("Учетная запись администратора создана. Пароль сохранен в виде BCrypt-хеша.");
    }

    public static string ReadNewPassword()
    {
        while (true)
        {
            string password = ConsoleInput.ReadPassword("Пароль (не менее 8 символов): ");
            string confirmation = ConsoleInput.ReadPassword("Повторите пароль: ");

            if (password != confirmation)
            {
                Console.WriteLine("Пароли не совпадают.");
                continue;
            }

            if (password.Length < 8)
            {
                Console.WriteLine("Пароль должен содержать не менее 8 символов.");
                continue;
            }

            if (Encoding.UTF8.GetByteCount(password) > 72)
            {
                Console.WriteLine("Для BCrypt длина пароля ограничена 72 байтами в UTF-8.");
                continue;
            }

            return password;
        }
    }

    private void Save()
    {
        string json = JsonSerializer.Serialize(_users, _jsonOptions);
        File.WriteAllText(_filePath, json);
    }
}
