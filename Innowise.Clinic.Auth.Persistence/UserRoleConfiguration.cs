using Innowise.Clinic.Auth.Constants;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Innowise.Clinic.Auth.Persistence;

public class UserRoleConfiguration : IEntityTypeConfiguration<IdentityRole<Guid>>
{
    public void Configure(EntityTypeBuilder<IdentityRole<Guid>> builder)
    {
        builder.HasData(
            new IdentityRole<Guid>
            {
                Id = Guid.Parse("8c1054b3-6986-468b-8583-72e5c53f5a20"),
                Name = UserRoles.Patient,
                NormalizedName = UserRoles.Patient.ToUpper()
            },
            new IdentityRole<Guid>
            {
                Id = Guid.Parse("1bb5d47f-bab5-4135-945c-60da30ea104d"),

                Name = UserRoles.Receptionist,
                NormalizedName = UserRoles.Receptionist.ToUpper()
            },
            new IdentityRole<Guid>()
            {
                Id = Guid.Parse("c1460814-4592-4cd9-944e-691db26b315e"),
                Name = UserRoles.Doctor,
                NormalizedName = UserRoles.Doctor.ToUpper()
            }
        );
    }
}