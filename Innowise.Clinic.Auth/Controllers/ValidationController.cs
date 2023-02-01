using Innowise.Clinic.Auth.Validators.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace Innowise.Clinic.Auth.Controllers;

[ApiController]
[Route("auth/validation")]
public class ValidationController : ControllerBase
{
    private const string EmailIsRegisteredMessage = "The account with the provided email is already registered in the system";
    private readonly IEmailValidator _emailValidator;

    public ValidationController(IEmailValidator emailValidator)
    {
        _emailValidator = emailValidator;
    }

    [HttpGet("email/{email:required}")]
    public async Task<IActionResult> CheckEmailUniqueness([FromRoute] string email)
    {
        var validationSucceeded = await _emailValidator.ValidateEmailAsync(email);

        return validationSucceeded? Ok() : BadRequest(EmailIsRegisteredMessage);
    }
}