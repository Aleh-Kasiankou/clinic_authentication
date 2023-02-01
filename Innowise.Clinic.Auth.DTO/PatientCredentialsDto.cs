using System.ComponentModel.DataAnnotations;

namespace Innowise.Clinic.Auth.DTO;

public class PatientCredentialsDto
{
    [EmailAddress]
    [Required(ErrorMessage = "Email is required")]
    public string Email { get; set; }
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)] 
    public string Password { get; set; }
}