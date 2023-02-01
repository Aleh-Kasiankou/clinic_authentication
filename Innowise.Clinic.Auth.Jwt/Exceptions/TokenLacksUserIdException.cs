namespace Innowise.Clinic.Auth.Jwt.Exceptions;

public class TokenLacksUserIdException : TokenValidationException
{
    private const string DefaultMessage = "The provided token lacks user identifier";
    
    public TokenLacksUserIdException() : base(DefaultMessage)
    {
    }
}