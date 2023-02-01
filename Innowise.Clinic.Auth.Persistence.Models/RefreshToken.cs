using Microsoft.AspNetCore.Identity;

namespace Innowise.Clinic.Auth.Persistence.Models;

public class RefreshToken
{
    public Guid TokenId { get; set; }
    public Guid UserId { get; set; }
    public virtual IdentityUser<Guid> User { get; set; }
}