using System.Security.Cryptography;
using System.Text;

namespace InfoSecContour.Services;

public class DpapiService
{
    private static readonly byte[] AdditionalEntropy = Encoding.UTF8.GetBytes("InfoSecContour-DPAPI-v1");

    public void ProtectToFile(string secret, string filePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "DPAPI доступен только в Windows. Запустите этот пункт на Windows под той же учетной записью.");
        }

        byte[] plainBytes = Encoding.UTF8.GetBytes(secret);
        try
        {
            byte[] protectedBytes = ProtectedData.Protect(
                plainBytes,
                AdditionalEntropy,
                DataProtectionScope.CurrentUser);

            File.WriteAllBytes(filePath, protectedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }

    public string UnprotectFromFile(string filePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "DPAPI доступен только в Windows. Запустите этот пункт на Windows под той же учетной записью.");
        }

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("Зашифрованный файл не найден.", filePath);
        }

        byte[] protectedBytes = File.ReadAllBytes(filePath);
        byte[] plainBytes = ProtectedData.Unprotect(
            protectedBytes,
            AdditionalEntropy,
            DataProtectionScope.CurrentUser);

        try
        {
            return Encoding.UTF8.GetString(plainBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }

}
