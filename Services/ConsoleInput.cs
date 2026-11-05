namespace InfoSecContour.Services;

public static class ConsoleInput
{
    public static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        var result = new List<char>();

        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);

            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return new string(result.ToArray());
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (result.Count > 0)
                {
                    result.RemoveAt(result.Count - 1);
                    Console.Write("\b \b");
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                result.Add(key.KeyChar);
                Console.Write('*');
            }
        }
    }

    public static string ReadRequired(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            string value = (Console.ReadLine() ?? string.Empty).Trim();

            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }

            Console.WriteLine("Значение не должно быть пустым.");
        }
    }
}
