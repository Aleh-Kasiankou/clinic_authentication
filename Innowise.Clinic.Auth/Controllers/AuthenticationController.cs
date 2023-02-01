using System.Security.Claims;
using Innowise.Clinic.Auth.Constants;
using Innowise.Clinic.Auth.DTO;
using Innowise.Clinic.Auth.Jwt.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Innowise.Clinic.Auth.Controllers;

[ApiController]
[Route("auth")]
public class AuthenticationController : ControllerBase
{
    private readonly UserManager<IdentityUser<Guid>> _userManager;
    private readonly ITokenGenerator _tokenGenerator;

    public AuthenticationController(UserManager<IdentityUser<Guid>> userManager, ITokenGenerator tokenGenerator)
    {
        _userManager = userManager;
        _tokenGenerator = tokenGenerator;
    }


    [HttpPost("sign-up/patient")]
    public async Task<ActionResult<AuthTokenPairDto>> RegisterPatient(PatientSignUpDto patientCredentials)
    {
        var userExists = await _userManager.FindByEmailAsync(patientCredentials.Email);
        if (userExists != null)
            return BadRequest();

        IdentityUser<Guid> user = new()
        {
            Email = patientCredentials.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = patientCredentials.Email
        };
        var signUpResult = await _userManager.CreateAsync(user, patientCredentials.Password);
        if (!signUpResult.Succeeded)
        {
            foreach (var error in signUpResult.Errors)
            {
                ModelState.TryAddModelError(error.Code, error.Description);
            }

            return BadRequest(ModelState);
        }

        await _userManager.AddToRoleAsync(user, UserRoles.Patient);

        var authTokens = await GenerateJwtAndRefreshToken(user);

        return Ok(authTokens);
    }
    
    [HttpPost("token/refresh")]
    public async Task<ActionResult<string>> RefreshToken([FromBody] AuthTokenPairDto tokens,
        [FromServices] ITokenValidator validator)
    {
        var principal = await validator.ValidateTokenPairAndExtractPrincipal(tokens);
        return _tokenGenerator.GenerateJwtToken(principal);
    }

    private async Task<AuthTokenPairDto> GenerateJwtAndRefreshToken(IdentityUser<Guid> user)
    {
        var principal = await GetRegisteredUserPrincipalAsync(user);
        var jwtToken = _tokenGenerator.GenerateJwtToken(principal);
        var refreshToken = await _tokenGenerator.GenerateRefreshTokenAsync(user.Id);
        var authTokens = new AuthTokenPairDto(jwtToken, refreshToken);

        return authTokens;
    }

    private async Task<ClaimsPrincipal> GetRegisteredUserPrincipalAsync(IdentityUser<Guid> user)
    {
        var getUserRolesTask = _userManager.GetRolesAsync(user);

        var authClaims = new List<Claim>
        {
            new(ClaimTypes.PrimarySid, user.Id.ToString()),
        };

        var userRoles = await getUserRolesTask;
        foreach (var userRole in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
        }

        var claimsIdentity = new ClaimsIdentity(authClaims);
        var principal = new ClaimsPrincipal(claimsIdentity);
        return principal;
    }
}