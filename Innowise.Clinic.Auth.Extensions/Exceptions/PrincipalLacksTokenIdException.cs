namespace Innowise.Clinic.Auth.Extensions.Exceptions;

public class PrincipalLacksTokenIdException : ApplicationException
{
    private const string DefaultMessage = "The principal lacks TokenID";
    
    public PrincipalLacksTokenIdException() : base(DefaultMessage)
    {
        
    }
}