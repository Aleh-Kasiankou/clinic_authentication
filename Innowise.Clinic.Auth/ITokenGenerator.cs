using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Innowise.Clinic.Auth;

public interface ITokenGenerator
{
    JwtSecurityToken GenerateToken(IEnumerable<Claim> authClaims);
}