using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Innowise.Clinic.Auth.DTO;
using Innowise.Clinic.Auth.Jwt.Exceptions;
using Innowise.Clinic.Auth.Jwt.Interfaces;
using Innowise.Clinic.Auth.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Innowise.Clinic.Auth.Jwt;

public class TokenValidator : ITokenValidator
{
    private readonly ClinicAuthDbContext _dbContext;
    private readonly IOptions<JwtData> _jwtConfiguration;

    public TokenValidator(ClinicAuthDbContext dbContext, IOptions<JwtData> jwtConfiguration)
    {
        _dbContext = dbContext;
        _jwtConfiguration = jwtConfiguration;
    }

    public async Task<ClaimsPrincipal> ValidateTokenPairAndExtractPrincipal(AuthTokenPairDto authTokens,
        bool tokenShouldBeExpired)
    {
        var principal = ExtractPrincipalFromJwtToken(authTokens.JwtToken, tokenShouldBeExpired);

        await ValidateRefreshTokenAsync(authTokens.RefreshToken);

        return principal;
    }

    private ClaimsPrincipal ExtractPrincipalFromJwtToken(string token, bool tokenShouldBeExpired)
    {
        var securityToken = new JwtSecurityToken(token);

        if (tokenShouldBeExpired && securityToken.ValidTo > DateTime.UtcNow)
        {
            throw new JwtTokenNotExpiredException();
        }

        var principal = ValidateTokenAndReturnPrinciple(token, false, out _);

        return principal;
    }

    private async Task ValidateRefreshTokenAsync(string token)
    {
        var principal = ValidateTokenAndReturnPrinciple(token, true, out var validatedToken);

        var extractedTokenId = principal.FindFirstValue("jti");
        var associatedUserId = principal.FindFirstValue(ClaimTypes.PrimarySid);

        if (extractedTokenId == null)
        {
            throw new TokenLacksTokenIdException();
        }

        if (associatedUserId == null)
        {
            throw new TokenLacksUserIdException();
        }

        var tokenIsRegisteredInDb = await _dbContext.RefreshTokens.AnyAsync(x =>
            x.TokenId == Guid.Parse(extractedTokenId) &&
            x.UserId == Guid.Parse(associatedUserId));


        if (!tokenIsRegisteredInDb)
        {
            throw new UnknownRefreshTokenException();
        }
    }

    private ClaimsPrincipal ValidateTokenAndReturnPrinciple(string token, bool validateExpirationDate,
        out SecurityToken validatedToken)
    {
        var jwtTokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _jwtConfiguration.Value.ValidIssuer,
            ValidateIssuerSigningKey = true,
            ValidateAudience = false,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfiguration.Value.Key)),
            ValidateLifetime = validateExpirationDate
        };

        var tokenHandler = new JwtSecurityTokenHandler();

        var principal = tokenHandler.ValidateToken(token, jwtTokenValidationParameters,
            out validatedToken);

        return principal;
    }
}