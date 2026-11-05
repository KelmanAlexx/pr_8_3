namespace InfoSecContour.Models;

public class CertificateCheckResult
{
    public bool IsValid { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public DateTime NotBeforeUtc { get; set; }
    public DateTime NotAfterUtc { get; set; }
    public List<string> ChainStatuses { get; set; } = new();
    public List<string> ChainSubjects { get; set; } = new();
}
