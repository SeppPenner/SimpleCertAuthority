// --------------------------------------------------------------------------------------------------------------------
// <copyright file="SimpleCertAuthorityService.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The main service class of the <see cref="SimpleCertAuthorityService" />.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority;

/// <inheritdoc cref="BackgroundService"/>
/// <summary>
/// The main service class of the <see cref="SimpleCertAuthorityService" />.
/// </summary>
public class SimpleCertAuthorityService : BackgroundService
{
    /// <summary>
    /// The logger.
    /// </summary>
    private readonly ILogger logger;

    /// <summary>
    /// The service name.
    /// </summary>
    private readonly string serviceName;

    /// <summary>
    /// The bytes divider. (Used to convert from bytes to kilobytes and so on).
    /// </summary>
    private static double BytesDivider => 1048576.0;

    /// <summary>
    /// The cancellation token.
    /// </summary>
    private CancellationToken cancellationToken;

    /// <summary>
    /// Gets or sets the simple cert authority configuration.
    /// </summary>
    public SimpleCertAuthorityConfiguration SimpleCertAuthorityConfiguration { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SimpleCertAuthorityService"/> class.
    /// </summary>
    /// <param name="simpleCertAuthorityConfiguration">The simple cert authority configuration.</param>
    /// <param name="serviceName">The service name.</param>
    public SimpleCertAuthorityService(SimpleCertAuthorityConfiguration simpleCertAuthorityConfiguration, string serviceName)
    {
        this.SimpleCertAuthorityConfiguration = simpleCertAuthorityConfiguration;
        this.serviceName = serviceName;

        // Create the logger.
        this.logger = LoggerConfig.GetLoggerConfiguration(nameof(SimpleCertAuthorityService))
            .WriteTo.Sink((ILogEventSink)Log.Logger)
            .CreateLogger();
    }

    /// <inheritdoc cref="BackgroundService"/>
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!this.SimpleCertAuthorityConfiguration.IsValid())
        {
            throw new Exception("The configuration is invalid");
        }

        this.logger.Information("Starting service");
        this.cancellationToken = cancellationToken;
        await this.StartService();
        this.logger.Information("Service started");
        await base.StartAsync(cancellationToken);
    }

    /// <inheritdoc cref="BackgroundService"/>
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
    }

    /// <inheritdoc cref="BackgroundService"/>
    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // Log some memory information.
                this.LogMemoryInformation();
                await Task.Delay(this.SimpleCertAuthorityConfiguration.DelayInMilliSeconds, cancellationToken);
            }
            catch (Exception ex)
            {
                this.logger.Error("An error occurred: {Exception}", ex);
            }
        }
    }

    /// <summary>
    /// Starts the service.
    /// </summary>
    private async Task StartService()
    {
        // Add the folders if they do not exist.
        DirectoryHelper.CreateDirectory(DirectoryNames.RootCertificates);
        DirectoryHelper.CreateDirectory(DirectoryNames.SubCaCertificates);
        DirectoryHelper.CreateDirectory(DirectoryNames.RevokedCertificates);
        DirectoryHelper.CreateDirectory(DirectoryNames.Keys);

        // Load the RSA key pair.
        var rsaKeyPairLoaded = await CertificateStore.LoadRsaKeyPair();

        // Create the RSA key pair if it was not loaded.
        if (!rsaKeyPairLoaded)
        {
            this.logger.Warning("RSA key pair not loaded, creating a new one");
            await CertificateStore.CreateAndSaveRsaKeyPair();
        }

        // Load the root certificates.
        var numberOfRootCertificates = await CertificateStore.LoadRootCertificates(this.SimpleCertAuthorityConfiguration.RootCaPassword);

        // Create a root certificate if none was loaded.
        if (numberOfRootCertificates == 0)
        {
            this.logger.Warning("No root certificate loaded, creating a new one");
            await CertificateStore.CreateAndSaveRootCertificate(
                this.SimpleCertAuthorityConfiguration.RootCaPassword,
                this.SimpleCertAuthorityConfiguration.RootCaSubject);
        }

        // Load the sub CA certificates.
        var numberOfSubCaCertificates = await CertificateStore.LoadSubCaCertificates(this.SimpleCertAuthorityConfiguration.SubCaPassword);

        // Create a sub CA certificate if none was loaded.
        if (numberOfSubCaCertificates == 0)
        {
            this.logger.Warning("No sub CA certificate loaded, creating a new one");
            await CertificateStore.CreateAndSaveSubCaCertificate(
                this.SimpleCertAuthorityConfiguration.SubCaPassword,
                this.SimpleCertAuthorityConfiguration.SubCaSubject);
        }

        // Load the revoked certificates.
        await CertificateStore.LoadRevokedCertificates();
    }

    /// <summary>
    /// Logs the heartbeat message with some memory information.
    /// </summary>
    private void LogMemoryInformation()
    {
        var totalMemory = GC.GetTotalMemory(false);
        var memoryInfo = GC.GetGCMemoryInfo();
        var divider = BytesDivider;
        Log.Information(
            "Heartbeat for service {ServiceName}: Total {Total}, heap size: {HeapSize}, memory load: {MemoryLoad}.",
            this.serviceName, $"{(totalMemory / divider):N3}", $"{(memoryInfo.HeapSizeBytes / divider):N3}", $"{(memoryInfo.MemoryLoadBytes / divider):N3}");
    }
}
