using System.Security.Cryptography.X509Certificates;
using InfoSecContour.Models;

namespace InfoSecContour.Services;

public class CertificateValidationService
{
    public CertificateCheckResult ValidateFile(string filePath, string? pfxPassword, bool checkRevocationOnline)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("Файл сертификата не найден.", filePath);
        }

        X509ContentType contentType = X509Certificate2.GetCertContentType(filePath);
        X509Certificate2 certificate;

        if (contentType == X509ContentType.Pkcs12)
        {
            certificate = X509CertificateLoader.LoadPkcs12FromFile(
                filePath,
                pfxPassword,
                X509KeyStorageFlags.EphemeralKeySet);
        }
        else if (contentType == X509ContentType.Cert)
        {
            certificate = X509CertificateLoader.LoadCertificateFromFile(filePath);
        }
        else
        {
            throw new InvalidOperationException("Поддерживаются сертификаты CER, CRT, PEM и контейнеры PFX/P12.");
        }

        using (certificate)
        using (X509Chain chain = new X509Chain())
        {
            chain.ChainPolicy.RevocationMode = checkRevocationOnline
                ? X509RevocationMode.Online
                : X509RevocationMode.NoCheck;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);

            bool isValid = chain.Build(certificate);

            var result = new CertificateCheckResult
            {
                IsValid = isValid,
                Subject = certificate.Subject,
                Issuer = certificate.Issuer,
                Thumbprint = certificate.Thumbprint,
                NotBeforeUtc = certificate.NotBefore.ToUniversalTime(),
                NotAfterUtc = certificate.NotAfter.ToUniversalTime()
            };

            foreach (X509ChainElement element in chain.ChainElements)
            {
                result.ChainSubjects.Add(element.Certificate.Subject);
            }

            foreach (X509ChainStatus status in chain.ChainStatus)
            {
                string message = status.StatusInformation.Trim();
                result.ChainStatuses.Add($"{status.Status}: {message}");
            }

            if (result.ChainStatuses.Count == 0)
            {
                result.ChainStatuses.Add("Ошибок цепочки не обнаружено.");
            }

            return result;
        }
    }
}
