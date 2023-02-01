using Innowise.Clinic.Auth.Persistence.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Innowise.Clinic.Auth.Persistence;

public class ClinicAuthDbContext : IdentityDbContext<IdentityUser<Guid>, IdentityRole<Guid>, Guid>
{
    public ClinicAuthDbContext(DbContextOptions<ClinicAuthDbContext> options) : base(options)
    {
    }

    public DbSet<RefreshToken> RefreshTokens { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfiguration(new UserRoleConfiguration());

        modelBuilder.Entity<RefreshToken>()
            .HasKey(x => x.TokenId);
        modelBuilder.Entity<RefreshToken>()
            .HasOne<IdentityUser<Guid>>(x => x.User)
            .WithMany()
            .HasForeignKey(x => x.UserId);
    }
}