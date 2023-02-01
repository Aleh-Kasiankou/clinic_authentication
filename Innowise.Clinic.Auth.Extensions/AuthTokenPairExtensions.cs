using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Innowise.Clinic.Auth.DTO;
using Innowise.Clinic.Auth.Extensions.Exceptions;
using Innowise.Clinic.Auth.Jwt.Exceptions;

namespace Innowise.Clinic.Auth.Extensions;

public static class AuthTokenPairExtensions
{
    public static Guid GetRefreshTokenId(this AuthTokenPairDto tokens)
    {
        var refreshToken = new JwtSecurityToken(tokens.RefreshToken);

        var tokenIdClaim = refreshToken.Claims.SingleOrDefault(x => x.Type == "jti");

        if (tokenIdClaim != null)
        {
            return Guid.Parse(tokenIdClaim.Value);
        }

        throw new PrincipalLacksTokenIdException();
    }
    
    public static Guid GetUserId(this AuthTokenPairDto tokens)
    {

        var refreshToken = new JwtSecurityToken(tokens.RefreshToken);
        
        var userIdClaim = refreshToken.Claims.SingleOrDefault(x => x.Type == ClaimTypes.PrimarySid);

        if (userIdClaim != null)
        {
            return Guid.Parse(userIdClaim.Value);
        }

        throw new TokenLacksUserIdException();
    }
}