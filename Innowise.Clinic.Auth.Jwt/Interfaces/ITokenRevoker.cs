namespace Innowise.Clinic.Auth.Jwt.Interfaces;

public interface ITokenRevoker
{
    Task RevokeTokenAsync(Guid tokenId);

    void RevokeToken(Guid tokenId);

    Task RevokeAllUserTokensAsync(Guid userId);

    void RevokeAllUserTokens(Guid userId);
    
    Task RevokeAllRefreshTokensAsync();

    void RevokeAllRefreshTokens();
}