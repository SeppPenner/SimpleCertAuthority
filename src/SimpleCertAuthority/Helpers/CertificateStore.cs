// --------------------------------------------------------------------------------------------------------------------
// <copyright file="CertificateStore.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The certificate store.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Helpers;

/// <summary>
/// The certificate store.
/// </summary>
public static class CertificateStore
{
    /// <summary>
    /// The RSA key pair.
    /// </summary>
    private static RSA? RsaKeyPair;

    /// <summary>
    /// The root certificates.
    /// </summary>
    private static readonly List<X509Certificate2> RootCertificates = [];

    /// <summary>
    /// The sub CA certificates.
    /// </summary>
    private static readonly List<X509Certificate2> SubCaCertificates = [];

    /// <summary>
    /// The revoked certificates (Serial numbers).
    /// </summary>
    private static readonly List<string> RevokedCertificates = [];

    /// <summary>
    /// Creates and saves the RSA key pair.
    /// </summary>
    /// <param name="keySize">The key size, defaults to 4096.</param>
    /// <exception cref="InvalidOperationException">Thrown if the RSA key was already generated.</exception>
    public static async Task CreateAndSaveRsaKeyPair(int keySize = 4096)
    {
        // Jump out if the key pair was already created before.
        if (RsaKeyPair is not null)
        {
            throw new InvalidOperationException("RSA key was already generated.");
        }

        // Create a new RSA key pair.
        using RSA rsa = RSA.Create(keySize);

        // Save private key in PEM format.
        var privateKeyFilePath = Path.Combine(DirectoryNames.Keys, NameConstants.PrivateKeyFileName);
        var privateKey = rsa.ExportRSAPrivateKey();
        await File.WriteAllBytesAsync(privateKeyFilePath, privateKey);

        // Save public key in PEM format.
        var publicKeyFilePath = Path.Combine(DirectoryNames.Keys, NameConstants.PublicKeyFileName);
        var publicKey = rsa.ExportRSAPublicKey();
        await File.WriteAllBytesAsync(publicKeyFilePath, publicKey);

        // Save the RSA key pair.
        RsaKeyPair = rsa;
    }

    /// <summary>
    /// Loads the RSA key pair.
    /// </summary>
    public static async Task<bool> LoadRsaKeyPair()
    {
        var privateKeyFilePath = Path.Combine(DirectoryNames.Keys, NameConstants.PrivateKeyFileName);
        var publicKeyFilePath = Path.Combine(DirectoryNames.Keys, NameConstants.PublicKeyFileName);

        // Check the key file paths.
        if (!File.Exists(privateKeyFilePath) || !File.Exists(publicKeyFilePath))
        {
            return false;
        }

        // Load the RSA private key.
        var privateKey = await File.ReadAllBytesAsync(privateKeyFilePath);
        var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKey, out _);

        // Load the RSA public key.
        var publicKey = await File.ReadAllBytesAsync(publicKeyFilePath);
        rsa.ImportRSAPublicKey(publicKey, out _);

        // Save the RSA key pair.
        RsaKeyPair = rsa;

        // The key pair was loaded successfully.
        return true;
    }

    /// <summary>
    /// Creates and saves a root certificate.
    /// </summary>
    /// <param name="rootCaPassword">The root CA password.</param>
    /// <param name="subjectName">The subject name.</param>
    /// <exception cref="InvalidOperationException">Thrown if the RSA key was not yet generated.</exception>
    public static async Task CreateAndSaveRootCertificate(string rootCaPassword, string subjectName)
    {
        // Jump out if the key pair was not yet created.
        if (RsaKeyPair is null)
        {
            throw new InvalidOperationException("RSA key was not yet generated. Please generate it first.");
        }

        // Create a certificate request for the root certificate.
        var request = new CertificateRequest(
            $"CN={subjectName}",
            RsaKeyPair,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add an extension to use as certification authority (CA).
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

        // Add key usage extensions for the root certification authority (CA).
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        // Add the subject key identifier (Helpful for chain tracking).
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        // Create a self-signed root certificate (e.g. valid for 5 years).
        var rootCert = request.CreateSelfSigned(
            DateTimeOffset.Now,
            DateTimeOffset.Now.AddYears(5));

        // Export certificate to PFX format.
        var certBytes = rootCert.Export(X509ContentType.Pfx, rootCaPassword);
        var certificateName = string.Format(NameConstants.RootCertificateFileName, RootCertificates.Count + 1);
        var rootCertificatePath = Path.Combine(DirectoryNames.RootCertificates, certificateName);
        await File.WriteAllBytesAsync(rootCertificatePath, certBytes);

        // Save root CA certificate.
        RootCertificates.Add(rootCert);
    }

    /// <summary>
    /// Loads all root certificates.
    /// </summary>
    /// <param name="rootCaPassword">The root CA password.</param>
    /// <returns>The number of root certificates.</returns>
    public static async Task<int> LoadRootCertificates(string rootCaPassword)
    {
        // Iterate over all root certificates.
        foreach (var file in Directory.GetFiles(DirectoryNames.RootCertificates))
        {
            // Load the certificate from the file.
            var certBytes = await File.ReadAllBytesAsync(file);
            var cert = new X509Certificate2(certBytes, rootCaPassword, X509KeyStorageFlags.PersistKeySet);
            RootCertificates.Add(cert);
        }

        return RootCertificates.Count;
    }

    /// <summary>
    /// Gets all root certificates.
    /// </summary>
    /// <returns>A <see cref="List{T}"/> of <see cref="X509Certificate2"/>s.</returns>
    public static List<X509Certificate2> GetRootCertificates()
    {
        return RootCertificates;
    }

    /// <summary>
    /// Creates and saves a sub CA certificate.
    /// </summary>
    /// <param name="subCaPassword">The sub CA password.</param>
    /// <param name="subjectName">The subject name.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the RSA key was not yet generated orthe root certificate is missing.
    /// </exception>
    public static async Task CreateAndSaveSubCaCertificate(string subCaPassword, string subjectName)
    {
        // Jump out if the key pair was not yet created.
        if (RsaKeyPair is null)
        {
            throw new InvalidOperationException("RSA key was not yet generated. Please generate it first.");
        }

        // Jump out if the root certificate is missing.
        if (RootCertificates.Count == 0)
        {
            throw new InvalidOperationException("Root certificate is missing. Please create it first.");
        }

        // Select the root certificate with the latest expiration date.
        var rootCert = RootCertificates
            .OrderByDescending(cert => cert.NotAfter)
            .FirstOrDefault() ?? throw new InvalidOperationException("Root certificate is missing. Please create it first.");

        // Get the root certificate's private key.
        using var rootPrivateKey = rootCert?.GetRSAPrivateKey();

        // Get the certificate request for the sub CA certificate.
        var request = new CertificateRequest(
            $"CN={subjectName}",
            RsaKeyPair,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add an extension to use as certification authority (CA).
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

        // Add key usage extensions for the root certification authority (CA).
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        // Add the subject key identifier (Helpful for chain tracking).
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        // Sign the sub CA certificate with the root certificate.
        var intermediateCert = request.Create(
            rootCert!,
            DateTimeOffset.Now,
            DateTimeOffset.Now.AddYears(3),
            new byte[] { 1, 2, 3, 4 });

        // Export certificate to PFX format.
        var certBytes = intermediateCert.Export(X509ContentType.Pfx, subCaPassword);
        var certificateName = string.Format(NameConstants.SubCaCertificateFileName, SubCaCertificates.Count + 1);
        var subCaCertificatePath = Path.Combine(DirectoryNames.SubCaCertificates, certificateName);
        await File.WriteAllBytesAsync(subCaCertificatePath, certBytes);

        // Save sub CA certificate.
        SubCaCertificates.Add(intermediateCert);
    }

    /// <summary>
    /// Loads all sub CA certificates.
    /// </summary>
    /// <param name="subCaPassword">The sub CA password.</param>
    /// <returns>The number of sub CA certificates.</returns>
    public static async Task<int> LoadSubCaCertificates(string subCaPassword)
    {
        // Iterate over all sub CA certificates.
        foreach (var file in Directory.GetFiles(DirectoryNames.SubCaCertificates))
        {
            // Load the certificate from the file.
            var certBytes = await File.ReadAllBytesAsync(file);
            var cert = new X509Certificate2(certBytes, subCaPassword, X509KeyStorageFlags.PersistKeySet);
            SubCaCertificates.Add(cert);
        }

        return SubCaCertificates.Count;
    }

    /// <summary>
    /// Gets all sub CA certificates.
    /// </summary>
    /// <returns>A <see cref="List{T}"/> of <see cref="X509Certificate2"/>s.</returns>
    public static List<X509Certificate2> GetSubCaCertificates()
    {
        return SubCaCertificates;
    }

    /// <summary>
    /// Gets all revoked certificate serial numbers.
    /// </summary>
    /// <returns>A <see cref="List{T}"/> of <see cref="string"/>s.</returns>
    public static List<string> GetRevokedCertificateSerialNumbers()
    {
        return RevokedCertificates;
    }

    /// <summary>
    /// Creates the certificate.
    /// </summary>
    /// <param name="subjectName">The subject name.</param>
    /// <param name="validFrom">The valid from date.</param>
    /// <param name="validTo">The valid to date.</param>
    /// <param name="sanDomains">The SAN domains.</param>
    /// <param name="certificatePassword">The certificate password.</param>
    /// <returns>The certificate.</returns>
    /// <exception cref="InvalidOperationException">Thrown if any input parameters are invalid.</exception>
    public static X509Certificate2 CreateCertificate(
        string subjectName,
        DateTimeOffset validFrom,
        DateTimeOffset validTo,
        string[] sanDomains,
        string? certificatePassword = null)
    {
        // Jump out if the dates don't fit.
        if (validFrom >= validTo)
        {
            throw new InvalidOperationException("The valid from date must be before the valid to date.");
        }

        // Jump out if the key pair was not yet created.
        if (RsaKeyPair is null)
        {
            throw new InvalidOperationException("RSA key was not yet generated. Please generate it first.");
        }

        // Jump out if the root certificate is missing.
        if (RootCertificates.Count == 0)
        {
            throw new InvalidOperationException("Root certificate is missing. Please create it first.");
        }

        // Jump out if the sub CA certificate is missing.
        if (SubCaCertificates.Count == 0)
        {
            throw new InvalidOperationException("Sub CA certificate is missing. Please create it first.");
        }

        // Check and adjust the subject name.
        subjectName = subjectName.Trim();

        if (subjectName.StartsWith("CN="))
        {
            subjectName = subjectName.Replace("CN=", string.Empty);
        }

        // Select the sub CA certificate with the latest expiration date.
        var subCaCertificate = SubCaCertificates
            .OrderByDescending(cert => cert.NotAfter)
            .FirstOrDefault() ?? throw new InvalidOperationException("Sub CA certificate is missing. Please create it first.");

        // Get the certificate request for the certificate.
        var request = new CertificateRequest(
                $"CN={subjectName}",
                RsaKeyPair,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

        // Add an extension for the digital signature and key encipherment.
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: true));

        // Add an extension for the server authentication.
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                [
                    new Oid(OidConstants.ServerAuthentication)
                ],
                critical: true));

        // Add subject alternative names (SANs) if available.
        if (sanDomains.Length > 0)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();

            foreach (var domain in sanDomains)
            {
                sanBuilder.AddDnsName(domain);
            }

            request.CertificateExtensions.Add(sanBuilder.Build());
        }

        // Add the authority key identifier from the sub CA certificate.
        if (subCaCertificate.Extensions[OidConstants.SubjectKeyIdentifier] is X509SubjectKeyIdentifierExtension subjectKeyIdentifier)
        {
            var rawData = new byte[subjectKeyIdentifier.RawData.Length + 4];
            // Format: 30 xx 80 xx [SKI bytes]
            rawData[0] = 0x30; // SEQUENCE
            rawData[1] = (byte)(subjectKeyIdentifier.RawData.Length + 2);
            rawData[2] = 0x80; // Context Specific 0
            rawData[3] = (byte)(subjectKeyIdentifier.RawData.Length);
            Buffer.BlockCopy(subjectKeyIdentifier.RawData, 2, rawData, 4, subjectKeyIdentifier.RawData.Length - 2);

            // Add the authority key identifier extension.
            var authorityKeyIdentifierExtension = new X509Extension(OidConstants.AuthorityKeyIdentifier, rawData, false);
            request.CertificateExtensions.Add(authorityKeyIdentifierExtension);
        }

        // Set some basic constraints (non-CA certificate).
        var basicConstraints = new X509BasicConstraintsExtension(
            certificateAuthority: false,
            hasPathLengthConstraint: false,
            pathLengthConstraint: 0,
            critical: true);
        request.CertificateExtensions.Add(basicConstraints);

        // Create the certificate.
        using var subCaPrivateKey = subCaCertificate.GetRSAPrivateKey() ?? throw new InvalidOperationException("The sub CA private key is missing.");

        // Fill the serial number.
        var serialNumber = new byte[16];
        RandomNumberGenerator.Fill(serialNumber);

        // Create the new certificate.
        var certificate = request.Create(
            subCaCertificate.SubjectName,
            X509SignatureGenerator.CreateForRSA(subCaPrivateKey, RSASignaturePadding.Pkcs1),
            validFrom,
            validTo,
            serialNumber);

        // Export the certificate.
        return new X509Certificate2(
            certificate.Export(X509ContentType.Pfx),
            certificatePassword,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
    }

    /// <summary>
    /// Validates the certificate.
    /// </summary>
    /// <param name="certificateToValidate">The certificate.</param>
    /// <param name="validationError">The validation error.</param>
    /// <returns>A value indicating whether the certificate is valid or not.</returns>
    public static bool ValidateCertificate(X509Certificate2 certificateToValidate, out string validationError)
    {
        validationError = string.Empty;

        try
        {
            // Check if the certificate is revoked.
            if (IsCertificateRevoked(certificateToValidate))
            {
                validationError = "The certificate is revoked.";
                return false;
            }

            // Get the matching root and sub CA certificates.
            var matchingCertificates = FindMatchingCertificates(certificateToValidate);

            if (!matchingCertificates.IsComplete)
            {
                validationError = matchingCertificates.ErrorMessage;
                return false;
            }

            // Verify the certificate chain.
            using var chain = new X509Chain();

            // Deactivate the online certificate revocation check.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            // Deactivate the Windows certificate store.
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

            // Add certificates to the custom trust store.
            chain.ChainPolicy.CustomTrustStore.Add(matchingCertificates.RootCertificate!);
            chain.ChainPolicy.CustomTrustStore.Add(matchingCertificates.SubCaCertificate!);

            // Set extra store for certificates.
            chain.ChainPolicy.ExtraStore.Add(matchingCertificates.SubCaCertificate!);
            chain.ChainPolicy.ExtraStore.Add(matchingCertificates.RootCertificate!);

            // Activate the custom trust store.
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

            // Verify the chain.
            var isValid = chain.Build(certificateToValidate);

            // Collect the validation errors.
            if (!isValid)
            {
                var errors = new List<string>();

                foreach (var element in chain.ChainElements)
                {
                    foreach (var status in element.ChainElementStatus)
                    {
                        if (status.Status != X509ChainStatusFlags.UntrustedRoot)
                        {
                            errors.Add($"Certificate '{element.Certificate.Subject}': {status.StatusInformation}");
                        }
                    }
                }

                validationError = string.Join(Environment.NewLine, errors);
            }

            return isValid;
        }
        catch (Exception ex)
        {
            validationError = $"Error while validating the certificate: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Renews the certificate.
    /// </summary>
    /// <param name="certificateToRenew">The certificate to renew.</param>
    /// <param name="validFrom">The valid from date.</param>
    /// <param name="validTo">The valid to date.</param>
    /// <param name="certificatePassword">The certificate password.</param>
    /// <returns>The new certificate.</returns>
    /// <exception cref="InvalidOperationException">Thrown if any input parameters are invalid.</exception>
    public static X509Certificate2 RenewCertificate(
        X509Certificate2 certificateToRenew,
        DateTimeOffset validFrom,
        DateTimeOffset validTo,
        string? certificatePassword = null)
    {
        // Jump out if the dates don't fit.
        if (validFrom >= validTo)
        {
            throw new InvalidOperationException("The valid from date must be before the valid to date.");
        }

        // Jump out if the key pair was not yet created.
        if (RsaKeyPair is null)
        {
            throw new InvalidOperationException("RSA key was not yet generated. Please generate it first.");
        }

        // Jump out if the root certificate is missing.
        if (RootCertificates.Count == 0)
        {
            throw new InvalidOperationException("Root certificate is missing. Please create it first.");
        }

        // Jump out if the sub CA certificate is missing.
        if (SubCaCertificates.Count == 0)
        {
            throw new InvalidOperationException("Sub CA certificate is missing. Please create it first.");
        }

        // Check whether the certificate is still valid or already expired.
        if (DateTime.Now > certificateToRenew.NotAfter)
        {
            throw new InvalidOperationException("The certificate is already expired.");
        }

        // Get the matching root and sub CA certificates.
        var matchingCertificates = FindMatchingCertificates(certificateToRenew);

        if (!matchingCertificates.IsComplete)
        {
            throw new InvalidOperationException(matchingCertificates.ErrorMessage);
        }

        // Get the certificate request for the certificate.
        var request = new CertificateRequest(
            certificateToRenew.Subject,
            RsaKeyPair,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Copy all relevant extensions from the old certificate.
        CopyRelevantExtensions(certificateToRenew, request);

        // Add the standard extensions if they are missing.
        AddStandardExtensionsIfMissing(request);

        // Add the subject alternative names (SANs) if available.
        CopySubjectAlternativeNames(certificateToRenew, request);

        // Add the authority key identifier from the sub CA certificate.
        AddAuthorityKeyIdentifier(matchingCertificates.SubCaCertificate!, request);

        // Create the certificate.
        using var subCaPrivateKey = matchingCertificates.SubCaCertificate!.GetRSAPrivateKey() ?? throw new InvalidOperationException("The sub CA private key is missing.");

        // Fill the serial number.
        var serialNumber = new byte[16];
        RandomNumberGenerator.Fill(serialNumber);

        // Create the new certificate.
        var certificate = request.Create(
            certificateToRenew.SubjectName,
            X509SignatureGenerator.CreateForRSA(subCaPrivateKey, RSASignaturePadding.Pkcs1),
            validFrom,
            validTo,
            serialNumber);

        // Export the certificate.
        return new X509Certificate2(
            certificate.Export(X509ContentType.Pfx),
            certificatePassword,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
    }

    /// <summary>
    /// Loads all revoked certificates.
    /// </summary>
    public static async Task LoadRevokedCertificates()
    {
        // Iterate over all revoked certificates.
        foreach (var file in Directory.GetFiles(DirectoryNames.RevokedCertificates))
        {
            // Load the certificates from the file.
            var fileContent = await File.ReadAllBytesAsync(file);
            var revokedCertificates = JsonSerializer.Deserialize<List<string>>(fileContent) ?? [];

            // Add the revoked certificates.
            if (revokedCertificates.Count != 0)
            {
                RevokedCertificates.AddRange(revokedCertificates);
            }
        }
    }

    /// <summary>
    /// Adds a revoked certificate.
    /// </summary>
    /// <param name="certificate">The revoked certificate.</param>
    public static async Task AddRevokedCertificate(string certificate)
    {
        // Add the revoked certificate.
        RevokedCertificates.Add(certificate);

        // Save the revoked certificates.
        await SaveRevokedCertificates();
    }

    /// <summary>
    /// Adds revoked certificates.
    /// </summary>
    /// <param name="certificates">The revoked certificates.</param>
    public static async Task AddRevokedCertificates(List<string> certificates)
    {
        // Add the revoked certificates.
        RevokedCertificates.AddRange(certificates);

        // Save the revoked certificates.
        await SaveRevokedCertificates();
    }

    /// <summary>
    /// Copies all relevant extensions.
    /// </summary>
    /// <param name="sourceCertificate">The source certificate.</param>
    /// <param name="certificateRequest">The certificate request.</param>
    private static void CopyRelevantExtensions(X509Certificate2 sourceCertificate, CertificateRequest certificateRequest)
    {
        foreach (var extension in sourceCertificate.Extensions)
        {
            // Skip special extensions.
            if (IsSpecialExtension(extension))
            {
                continue;
            }

            certificateRequest.CertificateExtensions.Add(extension);
        }
    }

    /// <summary>
    /// Checks whether an extension is a special extension or not.
    /// </summary>
    /// <param name="extension">The extension.</param>
    /// <returns>A value indicating whether an extension is a special extension or not.</returns>
    private static bool IsSpecialExtension(X509Extension extension)
    {
        var specialOids = new[]
        {
            OidConstants.SubjectKeyIdentifier,
            OidConstants.AuthorityKeyIdentifier,
            OidConstants.SubjectAlternativeName,
            OidConstants.BasicConstraints
        };

        return specialOids.Contains(extension.Oid?.Value);
    }

    /// <summary>
    /// Adds the standard extensions if they are missing.
    /// </summary>
    /// <param name="certificateRequest">The certificate request.</param>
    private static void AddStandardExtensionsIfMissing(CertificateRequest certificateRequest)
    {
        // Add key usage if needed.
        if (!certificateRequest.CertificateExtensions.Any(x => x.Oid?.Value == OidConstants.KeyUsage))
        {
            certificateRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    critical: true));
        }

        // Add enhanced key usage if needed.
        if (!certificateRequest.CertificateExtensions.Any(x => x.Oid?.Value == OidConstants.EnhancedKeyUsage))
        {
            // The server authentication.
            certificateRequest.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                [
                    new Oid(OidConstants.ServerAuthentication)
                ],
                critical: true));
        }

        // Add basic constraints if needed.
        if (!certificateRequest.CertificateExtensions.Any(x => x.Oid?.Value == OidConstants.BasicConstraints))
        {
            var basicConstraints = new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true);
            certificateRequest.CertificateExtensions.Add(basicConstraints);
        }
    }

    /// <summary>
    /// Copies the subject alternative names.
    /// </summary>
    /// <param name="sourceCertificate">The source certificate.</param>
    /// <param name="certificateRequest">The certificate request.</param>
    private static void CopySubjectAlternativeNames(X509Certificate2 sourceCertificate, CertificateRequest certificateRequest)
    {
        var sanExtension = sourceCertificate.Extensions
            .Cast<X509Extension>()
            .FirstOrDefault(x => x.Oid?.Value == OidConstants.SubjectAlternativeName);

        if (sanExtension is not null)
        {
            certificateRequest.CertificateExtensions.Add(sanExtension);
        }
    }

    /// <summary>
    /// Adds the authority key identifier.
    /// </summary>
    /// <param name="subCaCertificate">The sub CA certificate.</param>
    /// <param name="certificateRequest">The certificate request.</param>
    private static void AddAuthorityKeyIdentifier(X509Certificate2 subCaCertificate, CertificateRequest certificateRequest)
    {
        if (subCaCertificate.Extensions[OidConstants.SubjectKeyIdentifier] is X509SubjectKeyIdentifierExtension subCaSkiExt)
        {
            // Get the raw data.
            var rawData = new byte[subCaSkiExt.RawData.Length + 4];
            rawData[0] = 0x30; // Sequence.
            rawData[1] = (byte)(subCaSkiExt.RawData.Length + 2);
            rawData[2] = 0x80; // Context specific 0.
            rawData[3] = (byte)(subCaSkiExt.RawData.Length);
            Buffer.BlockCopy(subCaSkiExt.RawData, 2, rawData, 4, subCaSkiExt.RawData.Length - 2);

            // Adds the extension.
            var akiExtension = new X509Extension(OidConstants.AuthorityKeyIdentifier, rawData, false);
            certificateRequest.CertificateExtensions.Add(akiExtension);
        }
    }

    /// <summary>
    /// Finds the matching root and sub CA certificates for a certificate.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The <see cref="ChainResult"/>.</returns>
    private static ChainResult FindMatchingCertificates(X509Certificate2 certificate)
    {
        var result = new ChainResult();

        try
        {
            // Get the authority key identifier of the certificate.
            var certAki = GetAuthorityKeyIdentifier(certificate);

            if (string.IsNullOrWhiteSpace(certAki))
            {
                result.ErrorMessage = "No authority key identifier for certificate found.";
                return result;
            }

            // Search the matching sub CA certificate.
            result.SubCaCertificate = SubCaCertificates.FirstOrDefault(subCa =>
            {
                var subCaSki = GetSubjectKeyIdentifier(subCa);
                return !string.IsNullOrWhiteSpace(subCaSki) && subCaSki.Equals(certAki, StringComparison.OrdinalIgnoreCase);
            });

            // No matching sub CA found.
            if (result.SubCaCertificate is null)
            {
                result.ErrorMessage = "No matching sub CA certificate found.";
                return result;
            }

            // Get the authority key identifier of the sub CA certificate.
            var subCaAki = GetAuthorityKeyIdentifier(result.SubCaCertificate);

            if (string.IsNullOrWhiteSpace(subCaAki))
            {
                result.ErrorMessage = "No authority key identifier for sub CA certificate found.";
                return result;
            }

            // Search the matching root certificate.
            result.RootCertificate = RootCertificates.FirstOrDefault(rootCa =>
            {
                var rootCaSki = GetSubjectKeyIdentifier(rootCa);
                return !string.IsNullOrWhiteSpace(rootCaSki) && rootCaSki.Equals(subCaAki, StringComparison.OrdinalIgnoreCase);
            });

            if (result.RootCertificate is null)
            {
                result.ErrorMessage = "No matching root certificate found.";
                return result;
            }

            return result;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = $"Error while searching for root and sub CA certificates: {ex.Message}";
            return result;
        }
    }

    /// <summary>
    /// Gets the authority key identifier from a certificate.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The authority key identifier.</returns>
    private static string? GetAuthorityKeyIdentifier(X509Certificate2 certificate)
    {
        // Get the extension.
        var extension = certificate.Extensions.Cast<X509Extension>()
            .FirstOrDefault(ext => ext.Oid?.Value == OidConstants.AuthorityKeyIdentifier);

        if (extension is null)
        {
            return null;
        }

        // Get and return the authority key identifier.
        try
        {
            var rawData = extension.RawData;

            // Search: Typical after the first 0x80 tag.
            for (var i = 0; i < rawData.Length - 2; i++)
            {
                if (rawData[i] == 0x80)
                {
                    var length = rawData[i + 1];

                    if (length > 0 && i + 2 + length <= rawData.Length)
                    {
                        return BitConverter.ToString(rawData, i + 2, length).Replace("-", "");
                    }
                }
            }
        }
        catch
        {
            return null;
        }

        return null;
    }

    /// <summary>
    /// Gets the subject key identifier from a certificate.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The subject key identifier.</returns>
    private static string? GetSubjectKeyIdentifier(X509Certificate2 certificate)
    {
        // Get the extension.
        var extension = certificate.Extensions.Cast<X509Extension>()
            .FirstOrDefault(ext => ext.Oid?.Value == OidConstants.SubjectKeyIdentifier);

        if (extension is null)
        {
            return null;
        }

        // Get and return the subject key identifier.
        try
        {
            var subjectKeyIdentifier = new X509SubjectKeyIdentifierExtension(extension, false);
            return subjectKeyIdentifier.SubjectKeyIdentifier;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Checks if a certificate has been revoked based on its serial number.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>A value indicating whether the certificate is revoked or not.</returns>
    private static bool IsCertificateRevoked(X509Certificate2 certificate)
    {
        // Check if the serial number is in the revoked certificates list.
        return RevokedCertificates
            .Any(revoked => string.Equals(revoked, certificate.SerialNumber, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Saves the revoked certificates to a file.
    /// </summary>
    private static async Task SaveRevokedCertificates()
    {
        // Save the revoked certificates.
        var filePath = Path.Combine(DirectoryNames.RevokedCertificates, NameConstants.RevokedCertificatesFileName);
        var certBytes = JsonSerializer.SerializeToUtf8Bytes(RevokedCertificates);
        await File.WriteAllBytesAsync(filePath, certBytes);
    }
}
