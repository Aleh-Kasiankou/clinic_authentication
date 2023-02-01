namespace Innowise.Clinic.Auth.Jwt;

public class JwtData
{
    public string Key { get; set; }
    public string ValidIssuer { get; set; }

    public int TokenValidityInMinutes { get; set; }

    public int RefreshTokenValidityInDays { get; set; }
}