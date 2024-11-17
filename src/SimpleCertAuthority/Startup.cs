// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Startup.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The startup class.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority;

/// <summary>
/// The startup class.
/// </summary>
public sealed class Startup
{
    /// <summary>
    /// The service name.
    /// </summary>
    private readonly AssemblyName serviceName = Assembly.GetExecutingAssembly().GetName();

    /// <summary>
    /// Gets the simple cert authority configuration.
    /// </summary>
    private readonly SimpleCertAuthorityConfiguration simpleCertAuthorityConfiguration = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="Startup"/> class.
    /// </summary>
    /// <param name="configuration">The configuration.</param>
    public Startup(IConfiguration configuration)
    {
        configuration.GetSection(this.serviceName.Name ?? "SimpleCertAuthorityConfiguration").Bind(this.simpleCertAuthorityConfiguration);
    }

    /// <summary>
    /// Configures the services.
    /// </summary>
    /// <param name="services">The services.</param>
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddOptions();

        services.AddSingleton(this.simpleCertAuthorityConfiguration);

        services.AddAuthorization();
        services.AddAuthorizationCore();

        // Add authentication
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = $"SimpleCertAuthorityIssuer",
                ValidAudience = $"SimpleCertAuthorityAudience",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(this.simpleCertAuthorityConfiguration.JsonWebTokenConfigurationKey)),
                ClockSkew = TimeSpan.Zero
            };
        });

        services.AddMvc().AddRazorPagesOptions(options => { options.RootDirectory = "/"; })
            .AddDataAnnotationsLocalization();

        // Workaround to have a hosted background service available by DI.
        services.AddSingleton(_ => new SimpleCertAuthorityService(this.simpleCertAuthorityConfiguration, this.serviceName.Name ?? "SimpleCertAuthorityConfiguration"));
        services.AddSingleton<IHostedService>(p => p.GetRequiredService<SimpleCertAuthorityService>());

        services.AddControllers();

        // Add swagger document for the API
        services.AddOpenApiDocument(
            config =>
            {
                config.DocumentName = $"{this.serviceName.Name} {this.serviceName.Version}";
                config.PostProcess = document =>
                {
                    document.Info.Version = $"{this.serviceName.Version}";
                    document.Info.Title = $"{this.serviceName.Name}";
                    document.Info.Description = $"{this.serviceName.Name}";
                    document.Info.TermsOfService = "None";
                    document.Info.Contact = new OpenApiContact
                    {
                        Name = "Hämmer Electronics",
                        Email = string.Empty,
                        Url = "https://duckduckgo.com"
                    };
                    document.Info.License = new OpenApiLicense
                    {
                        Name = "Use prohibited unless explicitly allowed.",
                        Url = string.Empty
                    };
                };

                config.OperationProcessors.Add(new OperationSecurityScopeProcessor("auth"));
                config.DocumentProcessors.Add(new SecurityDefinitionAppender("auth", new OpenApiSecurityScheme
                {
                    Type = OpenApiSecuritySchemeType.Http,
                    In = OpenApiSecurityApiKeyLocation.Header,
                    Scheme = "bearer",
                    BearerFormat = "jwt"
                }));
            });
    }

    /// <summary>
    /// This method gets called by the runtime.
    /// </summary>
    /// <param name="app">The application.</param>
    /// <param name="env">The web hosting environment.</param>
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseSerilogRequestLogging();

        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();

        app.UseOpenApi();
        app.UseSwaggerUi();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapDefaultControllerRoute();
        });

        _ = app.ApplicationServices.GetService<SimpleCertAuthorityService>();
    }
}
