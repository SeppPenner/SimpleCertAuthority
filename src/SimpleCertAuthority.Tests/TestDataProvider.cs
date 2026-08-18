// --------------------------------------------------------------------------------------------------------------------
// <copyright file="TestDataProvider.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The data all test classes share.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Tests;

/// <summary>
/// The data all test classes share.
/// </summary>
internal static class TestDataProvider
{
    /// <summary>
    /// The root CA password.
    /// </summary>
    public const string RootCaPassword = "RootCaTestPassword";

    /// <summary>
    /// The sub CA password.
    /// </summary>
    public const string SubCaPassword = "SubCaTestPassword";

    /// <summary>
    /// The configured root CA subject. It carries the prefix the configuration file uses.
    /// </summary>
    public const string RootCaSubject = "CN=TestRootCa";

    /// <summary>
    /// The configured sub CA subject. It carries the prefix the configuration file uses.
    /// </summary>
    public const string SubCaSubject = "CN=TestSubCa";

    /// <summary>
    /// Creates a root certificate and a sub CA certificate, the state the service reaches while starting.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    public static async Task CreateCertificationAuthority()
    {
        await CertificateStore.CreateAndSaveRootCertificate(RootCaPassword, RootCaSubject);
        await CertificateStore.CreateAndSaveSubCaCertificate(SubCaPassword, SubCaSubject);
    }

    /// <summary>
    /// Issues a certificate that is valid right now.
    /// </summary>
    /// <param name="subjectName">The subject name.</param>
    /// <param name="sanDomains">The SAN domains.</param>
    /// <returns>The certificate including its private key.</returns>
    public static X509Certificate2 IssueCertificate(string subjectName = "test.example.com", params string[] sanDomains)
    {
        return CertificateStore.CreateCertificate(
            subjectName,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1),
            sanDomains);
    }

    /// <summary>
    /// Gets the public key of a certificate as a comparable <see cref="string"/>.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The public key.</returns>
    public static string GetPublicKey(X509Certificate2 certificate)
    {
        return Convert.ToHexString(certificate.PublicKey.EncodedKeyValue.RawData);
    }

    /// <summary>
    /// Gets the subject key identifier of a certificate.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The subject key identifier.</returns>
    public static string GetSubjectKeyIdentifier(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions[OidConstants.SubjectKeyIdentifier];
        Assert.IsNotNull(extension, "The certificate carries no subject key identifier.");
        return new X509SubjectKeyIdentifierExtension(extension, false).SubjectKeyIdentifier ?? string.Empty;
    }

    /// <summary>
    /// Gets the authority key identifier of a certificate.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The authority key identifier.</returns>
    public static string GetAuthorityKeyIdentifier(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions[OidConstants.AuthorityKeyIdentifier];
        Assert.IsNotNull(extension, "The certificate carries no authority key identifier.");
        var authorityKeyIdentifier = new X509AuthorityKeyIdentifierExtension(extension.RawData, extension.Critical);
        Assert.IsNotNull(authorityKeyIdentifier.KeyIdentifier, "The authority key identifier holds no key identifier.");
        return Convert.ToHexString(authorityKeyIdentifier.KeyIdentifier.Value.Span);
    }
}
