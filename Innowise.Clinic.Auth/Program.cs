using Innowise.Clinic.Auth.Extensions;
using Innowise.Clinic.Auth.Jwt;
using Innowise.Clinic.Auth.Persistence;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => options.ConfigureSwaggerJwtSupport());
builder.Services.AddDbContext<ClinicAuthDbContext>(
    opt => opt.UseSqlServer(builder.Configuration.GetConnectionString("default")));
builder.Services.AddAuthentication();
builder.Services.ConfigureCustomValidators();
builder.Services.ConfigureIdentity();
builder.Services.Configure<JwtData>(builder.Configuration.GetSection("JWT"));
builder.Services.ConfigureJwtAuthentication(builder.Configuration.GetSection("JWT"));

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;

    var context = services.GetRequiredService<ClinicAuthDbContext>();
    if (context.Database.GetPendingMigrations().Any())
    {
        context.Database.Migrate();
    }
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();

public partial class Program
{
}