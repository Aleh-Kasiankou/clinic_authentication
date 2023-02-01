namespace Innowise.Clinic.Auth.Validators.Interfaces;

public interface IEmailValidator
{
    bool ValidateEmail(string email);
    Task<bool> ValidateEmailAsync(string email);
}