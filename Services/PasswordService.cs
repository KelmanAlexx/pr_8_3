using System.Text;

namespace InfoSecContour.Services;

public class PasswordService
{
    public string CreateHash(string password)
    {
        ValidatePasswordLength(password);
        return BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
    }

    public bool Verify(string password, string hash)
    {
        ValidatePasswordLength(password);
        return BCrypt.Net.BCrypt.Verify(password, hash);
    }

    private static void ValidatePasswordLength(string password)
    {
        if (Encoding.UTF8.GetByteCount(password) > 72)
        {
            throw new ArgumentException("BCrypt принимает не более 72 байт пароля в UTF-8.");
        }
    }
}
