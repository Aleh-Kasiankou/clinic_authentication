using System;
using System.Linq;
using System.Threading.Tasks;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using Innowise.Clinic.Auth.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Innowise.Clinic.Auth.IntegrationTesting;

public class IntegrationTestingWebApplicationFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly TestcontainersContainer _dbContainer = new TestcontainersBuilder<TestcontainersContainer>()
        .WithImage("mcr.microsoft.com/mssql/server:2022-latest")
        .WithEnvironment("SA_PASSWORD", "secureMssqlServerPassw0rd").WithEnvironment(
            "ACCEPT_EULA", "Y").WithPortBinding(25585, 1433)
        .WithWaitStrategy(Wait.ForUnixContainer().UntilPortIsAvailable(1433)).Build();

    private const string TestConnectionString =
        "Server=localhost,25585;Database=AuthDb;User Id=SA;Password=secureMssqlServerPassw0rd;";

    public IntegrationTestingWebApplicationFactory()
    {
    }

    public T UseDbContext<T>(Func<ClinicAuthDbContext, T> func)
    {
        using (var scope = Services.CreateScope())
        {
            var scopedServices = scope.ServiceProvider;
            var db = scopedServices.GetRequiredService<ClinicAuthDbContext>();
            return func(db);
        }
    }
    
    public T UseConfiguration<T>(Func<IConfiguration, T> func)
    {
        using (var scope = Services.CreateScope())
        {
            var scopedServices = scope.ServiceProvider;
            var config = scopedServices.GetRequiredService<IConfiguration>();
            return func(config);
        }
    }
    
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType ==
                     typeof(DbContextOptions<ClinicAuthDbContext>));

            services.Remove(descriptor);


            services.AddDbContext<ClinicAuthDbContext>(options => { options.UseSqlServer(TestConnectionString); });
            
            
        });
    }

    public async Task InitializeAsync()
    {
        await _dbContainer.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _dbContainer.StopAsync();
        await base.DisposeAsync();
    }
}