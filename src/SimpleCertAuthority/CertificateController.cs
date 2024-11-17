// --------------------------------------------------------------------------------------------------------------------
// <copyright file="CertificateController.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The certificate controller.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority;

/// <summary>
/// The certificate controller.
/// </summary>
[Route("api/[controller]")]
[ApiController]
[OpenApiTag("Certificate", Description = "Certificate management.")]
public sealed class CertificateController : ControllerBase
{
    /// <summary>
    /// The simple cert authority configuration.
    /// </summary>
    private readonly SimpleCertAuthorityConfiguration simpleCertAuthorityConfiguration;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateController"/> class.
    /// </summary>
    /// <param name="simpleCertAuthorityConfiguration">The simple cert authority configuration.</param>
    public CertificateController(SimpleCertAuthorityConfiguration simpleCertAuthorityConfiguration)
    {
        this.simpleCertAuthorityConfiguration = simpleCertAuthorityConfiguration;
    }

    /// <summary>
    /// Gets all root certificates as ZIP file.
    /// </summary>
    /// <returns>
    /// A <see cref="List{T}"/> of <see cref="X509Certificate2"/>s.
    /// </returns>
    /// <remarks>
    /// Gets all root certificates as ZIP file.
    /// </remarks>
    /// <response code="200">Root certificates found.</response>
    /// <response code="500">Internal server error.</response>
    [ProducesResponseType(typeof(List<X509Certificate2>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status500InternalServerError)]
    [HttpGet("getRootCertificates")]
    [AllowAnonymous]
    public ActionResult<List<X509Certificate2>> GetRootCertificates()
    {
        try
        {
            var rootCertificates = CertificateStore.GetRootCertificates();
            return this.ReturnZipCertificatesFile(rootCertificates);
        }
        catch (Exception ex)
        {
            return this.InternalServerError($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Gets all sub CA certificates as ZIP file.
    /// </summary>
    /// <returns>
    /// A <see cref="List{T}"/> of <see cref="X509Certificate2"/>s.
    /// </returns>
    /// <remarks>
    /// Gets all sub CA certificates as ZIP file.
    /// </remarks>
    /// <response code="200">Sub CA certificates found.</response>
    /// <response code="500">Internal server error.</response>
    [ProducesResponseType(typeof(List<X509Certificate2>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status500InternalServerError)]
    [HttpGet("getSubCaCertificates")]
    [AllowAnonymous]
    public ActionResult<List<X509Certificate2>> GetSubCaCertificates()
    {
        try
        {
            var subCaCertificates = CertificateStore.GetSubCaCertificates();
            return this.ReturnZipCertificatesFile(subCaCertificates);
        }
        catch (Exception ex)
        {
            return this.InternalServerError($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Gets all revoked certificate serial numbers.
    /// </summary>
    /// <returns>
    /// A <see cref="List{T}"/> of <see cref="string"/>s.
    /// </returns>
    /// <remarks>
    /// Gets all revoked certificate serial numbers.
    /// </remarks>
    /// <response code="200">Revoked certificate serial numbers found.</response>
    /// <response code="500">Internal server error.</response>
    [ProducesResponseType(typeof(List<string>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status500InternalServerError)]
    [HttpGet("getRevokedCertificateSerialNumbers")]
    [AllowAnonymous]
    public ActionResult<List<string>> GetRevokedCertificateSerialNumbers()
    {
        try
        {
            var revokedCertificateSerialNumbers = CertificateStore.GetRevokedCertificateSerialNumbers();
            return this.Ok(revokedCertificateSerialNumbers);
        }
        catch (Exception ex)
        {
            return this.InternalServerError($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Creates a new root certificate.
    /// </summary>
    /// <returns>
    /// A created status.
    /// </returns>
    /// <remarks>
    /// Creates a new root certificate.
    /// </remarks>
    /// <response code="201">Root certificate created.</response>
    /// <response code="500">Internal server error.</response>
    [ProducesResponseType(typeof(string), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(string), StatusCodes.Status500InternalServerError)]
    [HttpPost("createRootCertificate")]
    [Authorize]
    public async Task<ActionResult> CreateRootCertificate()
    {
        try
        {
            await CertificateStore.CreateAndSaveRootCertificate(
                this.simpleCertAuthorityConfiguration.RootCaPassword,
                this.simpleCertAuthorityConfiguration.RootCaSubject);
            return this.Created();
        }
        catch (Exception ex)
        {
            return this.InternalServerError($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Creates a new sub CA certificate.
    /// </summary>
    /// <returns>
    /// A created status.
    /// </returns>
    /// <remarks>
    /// Creates a new sub CA certificate.
    /// </remarks>
    /// <response code="201">Sub CA certificate created.</response>
    /// <response code="500">Internal server error.</response>
    [ProducesResponseType(typeof(string), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(string), StatusCodes.Status500InternalServerError)]
    [HttpPost("createSubCaCertificate")]
    [Authorize]
    public async Task<ActionResult> CreateSubCaCertificate()
    {
        try
        {
            await CertificateStore.CreateAndSaveSubCaCertificate(
                this.simpleCertAuthorityConfiguration.SubCaPassword,
                this.simpleCertAuthorityConfiguration.SubCaSubject);
            return this.Created();
        }
        catch (Exception ex)
        {
            return this.InternalServerError($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Generates a new certificate.
    /// </summary>
    /// <param name="dtoCreateCertificate">The DTO to create a certificate.</param>
    /// <returns>
    /// A new <see cref="X509Certificate2"/> as file result.
    /// </returns>
    /// <remarks>
    /// Generates a new certificate.
    /// </remarks>
    /// <response code="200">New certificate generated.</response>
    /// <response code="500">Internal server error.</response>
    [ProducesResponseType(typeof(X509Certificate2), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status500InternalServerError)]
    [HttpPost("generateCertificate")]
    [AllowAnonymous]
    public ActionResult<X509Certificate2> GenerateCertificate([FromBody] DtoCreateCertificate dtoCreateCertificate)
    {
        try
        {
            // Create a certificate.
            var certificate = CertificateStore.CreateCertificate(
                dtoCreateCertificate.SubjectName,
                dtoCreateCertificate.ValidFrom,
                dtoCreateCertificate.ValidTo,
                dtoCreateCertificate.SanDomains,
                dtoCreateCertificate.CertificatePassword);

            // Get the certificate bytes and return a file result.
            var certificateBytes = certificate.Export(X509ContentType.Pfx, dtoCreateCertificate.CertificatePassword);
            return this.File(certificateBytes, ContentTypes.ApplicationPkcs12, NameConstants.CertificateFileName);
        }
        catch (Exception ex)
        {
            return this.InternalServerError($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Revokes a certificate.
    /// </summary>
    /// <param name="certificateBytes">The certificate bytes.</param>
    /// <returns>
    /// A revoked status.
    /// </returns>
    /// <remarks>
    /// Revokes a certificate.
    /// </remarks>
    /// <response code="200">Certificate revoked.</response>
    /// <response code="500">Internal server error.</response>
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status500InternalServerError)]
    [HttpPost("revokeCertificate")]
    [AllowAnonymous]
    public async Task<ActionResult<string>> RevokeCertificate([FromBody] byte[] certificateBytes)
    {
        try
        {
            var certificate = new X509Certificate2(certificateBytes);
            await CertificateStore.AddRevokedCertificate(certificate.SerialNumber);
            return this.Ok("Certificate revoked.");
        }
        catch (Exception ex)
        {
            return this.InternalServerError($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Verifies a certificate.
    /// </summary>
    /// <param name="certificateBytes">The certificate bytes.</param>
    /// <returns>
    /// An ok status <see cref="string"/> or an error <see cref="string"/>.
    /// </returns>
    /// <remarks>
    /// Verifies a certificate.
    /// </remarks>
    /// <response code="200">Certificate verified or not.</response>
    /// <response code="409">Error while validating certificate.</response>
    /// <response code="500">Internal server error.</response>
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(string), StatusCodes.Status500InternalServerError)]
    [HttpPost("verifyCertificate")]
    [AllowAnonymous]
    public ActionResult<string> VerifyCertificate([FromBody] byte[] certificateBytes)
    {
        try
        {
            var certificate = new X509Certificate2(certificateBytes);
            var isValid = CertificateStore.ValidateCertificate(certificate, out var error);

            if (isValid)
            {
                return this.Ok("Certificate verified.");
            }

            return this.Conflict(error);
        }
        catch (Exception ex)
        {
            return this.InternalServerError($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Renews a given certificate.
    /// </summary>
    /// <param name="dtoRenewCertificate">The DTO to renew a certificate.</param>
    /// <returns>
    /// A new <see cref="X509Certificate2"/>.
    /// </returns>
    /// <remarks>
    /// Renews a given certificate.
    /// </remarks>
    /// <response code="200">New certificate generated.</response>
    /// <response code="500">Internal server error.</response>
    [ProducesResponseType(typeof(X509Certificate2), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status500InternalServerError)]
    [HttpPost("renewCertificate")]
    [AllowAnonymous]
    public ActionResult<X509Certificate2> RenewCertificate([FromBody] DtoRenewCertificate dtoRenewCertificate)
    {
        try
        {
            // Create a new certificate.
            var certificate = new X509Certificate2(dtoRenewCertificate.CertificateBytes);
            var newCertificate = CertificateStore.RenewCertificate(
                certificate,
                dtoRenewCertificate.ValidFrom,
                dtoRenewCertificate.ValidTo,
                dtoRenewCertificate.CertificatePassword);

            // Get the new certificate bytes and return a file result.
            var certificateBytes = newCertificate.Export(X509ContentType.Pfx, dtoRenewCertificate.CertificatePassword);
            return this.File(certificateBytes, ContentTypes.ApplicationPkcs12, NameConstants.CertificateFileName);
        }
        catch (Exception ex)
        {
            return this.InternalServerError($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Returns a ZIP file with all certificates.
    /// </summary>
    /// <param name="certificates">The certificates.</param>
    /// <returns>The file result.</returns>
    private ActionResult ReturnZipCertificatesFile(List<X509Certificate2> certificates)
    {
        using var memoryStream = new MemoryStream();
        using var archive = new ZipArchive(memoryStream, ZipArchiveMode.Create, true);

        // Iterate all certificates.
        foreach (var certificate in certificates)
        {
            // Get the file name.
            var fileName = $"{certificate.Subject.Replace("CN=", "").Replace(",", "")}-{certificate.Thumbprint}.cer";

            // Add a new entry to the ZIP file.
            var entry = archive.CreateEntry(fileName);

            // Open the entry stream.
            using var entryStream = entry.Open();

            // Export the certificate as bytes.
            var certBytes = certificate.Export(X509ContentType.Cert);
            entryStream.Write(certBytes, 0, certBytes.Length);
        }

        // Reset the memory stream.
        memoryStream.Position = 0;

        // Return the ZIP file.
        return this.File(memoryStream.ToArray(), ContentTypes.ApplicationZip, NameConstants.CertificatesFileName);
    }
}
