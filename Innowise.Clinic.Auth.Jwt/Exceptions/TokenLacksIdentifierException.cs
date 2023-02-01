namespace Innowise.Clinic.Auth.Jwt.Exceptions;

public class TokenLacksTokenIdException : TokenValidationException
{
    private const string DefaultMessage = "The provided token lacks token identifier";
    public TokenLacksTokenIdException() : base(DefaultMessage)
    {
        
    }
}