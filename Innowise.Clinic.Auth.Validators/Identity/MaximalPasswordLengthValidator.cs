using Microsoft.AspNetCore.Identity;

namespace Innowise.Clinic.Auth.Validators.Identity;

public class MaximalPasswordLengthValidator<TUser> : IPasswordValidator<TUser>
    where TUser : IdentityUser<Guid>
{
    private const int MaximalPasswordLength = 15;


    public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
    {
        if (password.Length > MaximalPasswordLength)
        {
            return await Task.FromResult(IdentityResult.Failed(new IdentityError
            {
                Code = "PasswordLength",
                Description = "The password should contain 6 to 15 symbols"
            }));
        }

        return await Task.FromResult(IdentityResult.Success);
    }
}