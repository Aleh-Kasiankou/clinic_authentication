using System.Security.Claims;

namespace Innowise.Clinic.Auth.Jwt.Interfaces;

public interface ITokenGenerator
{
    string GenerateJwtToken(ClaimsPrincipal principal);
    Task<string> GenerateRefreshTokenAsync(Guid userId);
}