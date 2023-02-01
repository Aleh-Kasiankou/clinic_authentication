using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Innowise.Clinic.Auth.Jwt.Interfaces;
using Innowise.Clinic.Auth.Persistence;
using Innowise.Clinic.Auth.Persistence.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Innowise.Clinic.Auth.Jwt;

public class TokenGenerator : ITokenGenerator
{
    private readonly IOptions<JwtData> _jwtOptions;
    private readonly SymmetricSecurityKey _securityKey;
    private readonly ClinicAuthDbContext _dbContext;

    public TokenGenerator(IOptions<JwtData> jwtOptions, ClinicAuthDbContext dbContext)
    {
        _jwtOptions = jwtOptions;
        _dbContext = dbContext;
        _securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.Value.Key));
    }

    public string GenerateJwtToken(ClaimsPrincipal principal)
    {
        var expirationDate = DateTime.UtcNow.AddMinutes(_jwtOptions.Value.TokenValidityInMinutes);

        var token = IssueToken(expirationDate, principal.Claims);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<string> GenerateRefreshTokenAsync(Guid userId)
    {
        var expirationDate = DateTime.UtcNow.AddDays(_jwtOptions.Value.RefreshTokenValidityInDays);

        var tokenId = await RegisterIssuedRefreshTokenInDbAsync(userId, expirationDate);

        var refreshTokenClaimsCollection = new List<Claim>
        {
            new("jti", tokenId.ToString()),
            new(ClaimTypes.PrimarySid, userId.ToString())
        };

        var token = IssueToken(expirationDate, refreshTokenClaimsCollection);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private JwtSecurityToken IssueToken(DateTime expirationDate, IEnumerable<Claim> claims)
    {
        return new JwtSecurityToken(
            issuer: _jwtOptions.Value.ValidIssuer,
            expires: expirationDate,
            signingCredentials: new SigningCredentials(_securityKey, SecurityAlgorithms.HmacSha256),
            claims: claims
        );
    }

    private async Task<Guid> RegisterIssuedRefreshTokenInDbAsync(Guid userId, DateTime expirationDate)
    {
        var refreshToken = new RefreshToken()
        {
            UserId = userId,
        };

        await _dbContext.RefreshTokens.AddAsync(refreshToken);
        await _dbContext.SaveChangesAsync();

        return refreshToken.TokenId;
    }
}