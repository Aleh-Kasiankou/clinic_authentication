using System.Security.Claims;
using Innowise.Clinic.Auth.DTO;

namespace Innowise.Clinic.Auth.Jwt.Interfaces;

public interface ITokenValidator
{
    Task<ClaimsPrincipal> ValidateTokenPairAndExtractPrincipal(AuthTokenPairDto authTokens);
}