namespace InfoSecContour.Services;

public class AuditService
{
    private readonly string _filePath;

    public AuditService(string dataDirectory)
    {
        _filePath = Path.Combine(dataDirectory, "audit.log");
    }

    public void Write(string username, string action, string result)
    {
        string safeUsername = Clean(username);
        string safeAction = Clean(action);
        string safeResult = Clean(result);
        string line = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z | {safeUsername} | {safeAction} | {safeResult}";

        File.AppendAllText(_filePath, line + Environment.NewLine);
    }

    public void ShowLastEntries(int count)
    {
        if (!File.Exists(_filePath))
        {
            Console.WriteLine("Журнал пока пуст.");
            return;
        }

        string[] lines = File.ReadAllLines(_filePath);
        int startIndex = Math.Max(0, lines.Length - count);

        Console.WriteLine("\nПоследние записи журнала:");
        for (int i = startIndex; i < lines.Length; i++)
        {
            Console.WriteLine(lines[i]);
        }
    }

    private static string Clean(string value)
    {
        return value.Replace('\r', ' ').Replace('\n', ' ').Replace('|', '/');
    }
}
