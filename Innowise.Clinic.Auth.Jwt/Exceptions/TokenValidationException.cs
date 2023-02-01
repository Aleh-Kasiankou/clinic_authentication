namespace Innowise.Clinic.Auth.Jwt.Exceptions;

public abstract class TokenValidationException : ApplicationException
{
    public TokenValidationException(string message) : base(message)
    {
        
    }
}