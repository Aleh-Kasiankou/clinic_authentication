using Innowise.Clinic.Auth.Persistence;
using Innowise.Clinic.Auth.Validators.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Innowise.Clinic.Auth.Validators.Custom;

public class EmailUniquenessValidator : IEmailValidator
{
    private readonly ClinicAuthDbContext _dbContext;

    public EmailUniquenessValidator(ClinicAuthDbContext dbContext)
    {
        _dbContext = dbContext;
    }
    
    public bool ValidateEmail(string email)
    {
        return !_dbContext.Users.Any(x => x.Email == email);
    }

    public async Task<bool> ValidateEmailAsync(string email)
    {
        return !await _dbContext.Users.AnyAsync(x => x.Email == email);

    }
}