using InfoSecContour.Models;

namespace InfoSecContour.Services;

public static class AuthorizationService
{
    public static bool HasPermission(UserRole role, Permission permission)
    {
        if (role == UserRole.Administrator)
        {
            return true;
        }

        if (role == UserRole.SecurityOperator)
        {
            return permission != Permission.ManageUsers;
        }

        if (role == UserRole.Auditor)
        {
            return permission == Permission.ValidateCertificate ||
                   permission == Permission.ViewAuditLog;
        }

        return false;
    }
}
