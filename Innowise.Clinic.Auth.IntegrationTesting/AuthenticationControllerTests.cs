using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Innowise.Clinic.Auth.Constants;
using Innowise.Clinic.Auth.DTO;
using Innowise.Clinic.Auth.Persistence.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Innowise.Clinic.Auth.IntegrationTesting;

public class AuthenticationControllerTests : IClassFixture<IntegrationTestingWebApplicationFactory>
{
    private readonly IntegrationTestingWebApplicationFactory _factory;
    private readonly HttpClient _httpClient;
    private readonly Guid _patientRoleId;

    private const string SignUpEndpointUri = "auth/sign-up/patient";
    private const string RefreshTokenEndpointUri = "auth/token/refresh";


    public AuthenticationControllerTests(IntegrationTestingWebApplicationFactory factory)
    {
        _factory = factory;
        _httpClient = factory.CreateClient(new WebApplicationFactoryClientOptions()
        {
            AllowAutoRedirect = false
        });

        _patientRoleId = _factory.UseDbContext(x => x.Roles.Single(r => r.Name == UserRoles.Patient).Id);
    }

    private static int _uniqueNumber = 0;

    private static int UniqueNumber => _uniqueNumber++;

    #region RegistrationTests

    [Fact]
    public async Task TestPatientWithValidEmailAndPasswordRegistered_OK()
    {
        // Arrange

        var validUserRegistrationData = new PatientSignUpDto()
        {
            Email = $"test{UniqueNumber}@test.com",
            Password = "12345678"
        };

        // Act

        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, validUserRegistrationData);

        // Assert

        Assert.True(response.IsSuccessStatusCode);
        Assert.True(_factory.UseDbContext(x => x.Users.Any(u => u.Email == validUserRegistrationData.Email)));

        var generatedTokens = await response.Content.ReadFromJsonAsync<AuthTokenPairDto>();
        var userId = ExtractUserIdFromJwtToken(generatedTokens.JwtToken);

        Assert.True(_factory.UseDbContext(x => x.UserRoles
            .Any(ur => ur.RoleId == _patientRoleId && ur.UserId == userId)));
    }

    [Fact]
    public async Task TestPatientWithInvalidEmailAndValidPasswordRegistered_Fail()
    {
        // Arrange

        var userRegistrationDataWithInvalidMail = new PatientSignUpDto()
        {
            Email = "testInvalidEmail",
            Password = "12345678"
        };

        // Act

        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, userRegistrationDataWithInvalidMail);

        // Assert

        Assert.False(response.IsSuccessStatusCode);
        Assert.False(_factory.UseDbContext(x => x.Users
            .Any(u => u.Email == userRegistrationDataWithInvalidMail.Email)));
    }

    [Fact]
    public async Task TestPatientWithValidEmailAndTooShortPasswordRegistered_Fail()
    {
        // Arrange

        var userRegistrationDataWithShortPassword = new PatientSignUpDto()
        {
            Email = $"test{UniqueNumber}@test.gmail.com",
            Password = "12345"
        };

        // Act

        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, userRegistrationDataWithShortPassword);

        // Assert

        Assert.False(response.IsSuccessStatusCode);
        Assert.False(_factory.UseDbContext(x => x.Users
            .Any(u => u.Email == userRegistrationDataWithShortPassword.Email)));
    }

    [Fact]
    public async Task TestPatientWithValidEmailAndTooLongPasswordRegistered_Fail()
    {
        // Arrange

        var userRegistrationDataWithLongPassword = new PatientSignUpDto()
        {
            Email = $"test{UniqueNumber}@test.gmail.com",
            Password = "12345678911131517"
        };

        // Act

        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, userRegistrationDataWithLongPassword);

        // Assert

        Assert.False(response.IsSuccessStatusCode);
        Assert.False(_factory.UseDbContext(x => x.Users
            .Any(u => u.Email == userRegistrationDataWithLongPassword.Email)));
    }


    [Fact]
    public async Task TestPatientWithNonUniqueEmailAndValidPasswordRegistered_Fail()
    {
        // Arrange

        var validEmail = $"test{UniqueNumber}@test.gmail.com";

        var userRegistrationDataWithRegisteredEmail = new PatientSignUpDto()
        {
            Email = validEmail,
            Password = "12345678"
        };

        // Act

        await _httpClient.PostAsJsonAsync(SignUpEndpointUri, userRegistrationDataWithRegisteredEmail);
        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, userRegistrationDataWithRegisteredEmail);

        // Assert

        Assert.False(response.IsSuccessStatusCode);
        Assert.Equal(1, _factory.UseDbContext(x => x.Users
            .Count(u => u.Email == userRegistrationDataWithRegisteredEmail.Email)));
    }

    #endregion

    #region TokenGenerationTests

    [Fact]
    public async Task TestRegisteredUserWithValidEmailAndPasswordGetsValidTokens_OK()
    {
        // Arrange

        var validUserRegistrationData = new PatientSignUpDto()
        {
            Email = $"test{UniqueNumber}@test.gmail.com",
            Password = "12345678"
        };

        // Act

        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, validUserRegistrationData);

        // Assert

        Assert.True(response.IsSuccessStatusCode);

        var generatedTokens = await response.Content.ReadFromJsonAsync<AuthTokenPairDto>();

        Assert.NotNull(generatedTokens);
        Assert.NotNull(generatedTokens.JwtToken);
        Assert.NotNull(generatedTokens.RefreshToken);

        var userId = ExtractUserIdFromJwtToken(generatedTokens.JwtToken);
        var refreshTokenId = ExtractRefreshTokenId(generatedTokens.RefreshToken);


        Assert.True(_factory.UseDbContext(x => x.RefreshTokens
            .Any(rt => rt.TokenId == refreshTokenId && rt.UserId == userId)));
    }

    [Fact]
    public async Task TestExpiredJwtTokenRefreshedWithValidRefreshToken_OK()
    {
        // Arrange

        var validEmail = $"test{UniqueNumber}@test.gmail.com";

        var userRegistrationDataWithRegisteredEmail = new PatientSignUpDto()
        {
            Email = validEmail,
            Password = "12345678"
        };

        // Act

        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, userRegistrationDataWithRegisteredEmail);
        var generatedTokens = await response.Content.ReadFromJsonAsync<AuthTokenPairDto>();

        await Task.Delay(_factory.UseConfiguration(x => x.GetValue<int>("JWT:TokenValidityInMinutes") * 60000));

        response = await _httpClient.PostAsJsonAsync(RefreshTokenEndpointUri, generatedTokens);
        var refreshedToken = await response.Content.ReadAsStringAsync();
        // Assert

        Assert.True(response.IsSuccessStatusCode);
        ValidateJwtToken(refreshedToken);
    }

    [Fact]
    public async Task TestValidActiveJwtTokenRefreshedWithValidRefreshToken_Fail()
    {
        // Arrange

        var validEmail = $"test{UniqueNumber}@test.gmail.com";

        var userRegistrationDataWithRegisteredEmail = new PatientSignUpDto()
        {
            Email = validEmail,
            Password = "12345678"
        };

        // Act

        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, userRegistrationDataWithRegisteredEmail);
        var generatedTokens = await response.Content.ReadFromJsonAsync<AuthTokenPairDto>();
        response = await _httpClient.PostAsJsonAsync(RefreshTokenEndpointUri, generatedTokens);
        // Assert

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task TestExpiredJwtTokenWithWrongSecurityKeyRefreshedWithValidRefreshToken_Fail()
    {
        // Arrange

        var validEmail = $"test{UniqueNumber}@test.gmail.com";

        var userRegistrationDataWithRegisteredEmail = new PatientSignUpDto()
        {
            Email = validEmail,
            Password = "12345678"
        };

        // Act

        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, userRegistrationDataWithRegisteredEmail);
        var generatedTokens = await response.Content.ReadFromJsonAsync<AuthTokenPairDto>();

        var invalidJwtToken = new JwtSecurityToken(
            issuer: _factory.UseConfiguration(x => x.GetValue<string>("JWT:ValidIssuer")),
            expires: DateTime.UtcNow - TimeSpan.FromHours(1),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes("123456791011121314151617181920")),
                SecurityAlgorithms.HmacSha256),
            claims: ValidateJwtToken(generatedTokens.JwtToken).Claims
        );

        var invalidTokenJson = new JwtSecurityTokenHandler().WriteToken(invalidJwtToken);

        response = await _httpClient.PostAsJsonAsync(RefreshTokenEndpointUri,
            new AuthTokenPairDto(invalidTokenJson, generatedTokens.RefreshToken));

        // Assert

        Assert.False(response.IsSuccessStatusCode);
        Assert.ThrowsAny<Exception>(delegate { ValidateJwtToken(invalidTokenJson); });
    }

    [Fact]
    public async Task TestExpiredJwtTokenWithWrongIssuerRefreshedWithValidRefreshToken_Fail()
    {
        // Arrange

        var validEmail = $"test{UniqueNumber}@test.gmail.com";

        var userRegistrationDataWithRegisteredEmail = new PatientSignUpDto()
        {
            Email = validEmail,
            Password = "12345678"
        };

        // Act

        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, userRegistrationDataWithRegisteredEmail);
        var generatedTokens = await response.Content.ReadFromJsonAsync<AuthTokenPairDto>();

        var invalidJwtToken = new JwtSecurityToken(
            issuer: "WrongIssuer",
            expires: DateTime.UtcNow - TimeSpan.FromHours(1),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(_factory.UseConfiguration(x => x.GetValue<string>("JWT:Key")))),
                SecurityAlgorithms.HmacSha256),
            claims: ValidateJwtToken(generatedTokens.JwtToken).Claims
        );

        var invalidTokenJson = new JwtSecurityTokenHandler().WriteToken(invalidJwtToken);

        response = await _httpClient.PostAsJsonAsync(RefreshTokenEndpointUri,
            new AuthTokenPairDto(invalidTokenJson, generatedTokens.RefreshToken));

        // Assert

        Assert.False(response.IsSuccessStatusCode);
        Assert.ThrowsAny<Exception>(delegate { ValidateJwtToken(invalidTokenJson); });
    }

    [Fact]
    public async Task TestValidExpiredJwtTokenRefreshedWithRefreshTokenWithWrongSecurityKey_Fail()
    {
        // Arrange

        var validEmail = $"test{UniqueNumber}@test.gmail.com";

        var userRegistrationDataWithRegisteredEmail = new PatientSignUpDto()
        {
            Email = validEmail,
            Password = "12345678"
        };

        // Act

        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, userRegistrationDataWithRegisteredEmail);
        var generatedTokens = await response.Content.ReadFromJsonAsync<AuthTokenPairDto>();


        var invalidRefreshToken = new JwtSecurityToken(
            issuer: _factory.UseConfiguration(x => x.GetValue<string>("JWT:ValidIssuer")),
            expires: DateTime.UtcNow - TimeSpan.FromHours(1),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes("123456791011121314151617181920")),
                SecurityAlgorithms.HmacSha256),
            claims: ValidateJwtToken(generatedTokens.RefreshToken).Claims
        );

        var invalidTokenJson = new JwtSecurityTokenHandler().WriteToken(invalidRefreshToken);

        await Task.Delay(_factory.UseConfiguration(x => x.GetValue<int>("JWT:TokenValidityInMinutes") * 60000));


        response = await _httpClient.PostAsJsonAsync(RefreshTokenEndpointUri,
            new AuthTokenPairDto(generatedTokens.JwtToken, invalidTokenJson));

        // Assert

        Assert.False(response.IsSuccessStatusCode);
        Assert.ThrowsAny<Exception>(delegate { ValidateJwtToken(invalidTokenJson); });
    }

    [Fact]
    public async Task TestValidExpiredJwtTokenRefreshedWithRefreshTokenWithWrongIssuer_Fail()
    {
        // Arrange

        var validEmail = $"test{UniqueNumber}@test.gmail.com";

        var userRegistrationDataWithRegisteredEmail = new PatientSignUpDto()
        {
            Email = validEmail,
            Password = "12345678"
        };

        // Act

        var response = await _httpClient.PostAsJsonAsync(SignUpEndpointUri, userRegistrationDataWithRegisteredEmail);
        var generatedTokens = await response.Content.ReadFromJsonAsync<AuthTokenPairDto>();


        var invalidRefreshToken = new JwtSecurityToken(
            issuer: "WrongIssuee",
            expires: DateTime.UtcNow - TimeSpan.FromHours(1),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(_factory.UseConfiguration(x => x.GetValue<string>("JWT:Key")))),
                SecurityAlgorithms.HmacSha256),
            claims: ValidateJwtToken(generatedTokens.RefreshToken).Claims
        );

        var invalidTokenJson = new JwtSecurityTokenHandler().WriteToken(invalidRefreshToken);

        await Task.Delay(_factory.UseConfiguration(x => x.GetValue<int>("JWT:TokenValidityInMinutes") * 60000));

        response = await _httpClient.PostAsJsonAsync(RefreshTokenEndpointUri,
            new AuthTokenPairDto(generatedTokens.JwtToken, invalidTokenJson));

        // Assert

        Assert.False(response.IsSuccessStatusCode);
        Assert.ThrowsAny<Exception>(delegate { ValidateJwtToken(invalidTokenJson); });
    }

    #endregion


    private ClaimsPrincipal ValidateJwtToken(string token)
    {
        var jwtToken = new JwtSecurityToken(token);
        var jwtTokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _factory.UseConfiguration(x => x.GetValue<string>("JWT:ValidIssuer")),
            ValidateIssuerSigningKey = true,
            ValidateAudience = false,
            IssuerSigningKey =
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(_factory.UseConfiguration(x => x.GetValue<string>("JWT:Key")))),
            ValidateLifetime = true
        };

        var tokenHandler = new JwtSecurityTokenHandler();

        return tokenHandler.ValidateToken(token, jwtTokenValidationParameters,
            out _);
    }

    private Guid ExtractUserIdFromJwtToken(string token)
    {
        var jwtToken = new JwtSecurityToken(token);
        var userId = jwtToken.Claims.First(x => x.Type == ClaimTypes.PrimarySid).Value;
        return Guid.Parse(userId);
    }

    private Guid ExtractRefreshTokenId(string refreshToken)
    {
        var refreshJwtToken = new JwtSecurityToken(refreshToken);
        var tokenId = refreshJwtToken.Claims.First(x => x.Type == "jti").Value;
        return Guid.Parse(tokenId);
    }
}