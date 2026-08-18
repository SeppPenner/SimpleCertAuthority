// --------------------------------------------------------------------------------------------------------------------
// <copyright file="CertificateHelperTests.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   Tests the <see cref="CertificateHelper" />.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Tests;

/// <summary>
/// Tests the <see cref="CertificateHelper"/>.
/// </summary>
[TestClass]
public sealed class CertificateHelperTests
{
    /// <summary>
    /// The password of the PKCS#12 test data.
    /// </summary>
    private const string Password = "HelperTestPassword";

    /// <summary>
    /// Creates a self-signed certificate to load from.
    /// </summary>
    /// <returns>The certificate including its private key.</returns>
    private static X509Certificate2 CreateCertificate()
    {
        using var keyPair = RSA.Create(2048);
        var request = new CertificateRequest("CN=helper.example.com", keyPair, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    }

    /// <summary>
    /// Tests that a plain certificate is loaded.
    /// </summary>
    [TestMethod]
    public void LoadFromBytes_ReadsAPlainCertificate()
    {
        using var source = CreateCertificate();
        var certificateBytes = source.Export(X509ContentType.Cert);

        using var loaded = CertificateHelper.LoadFromBytes(certificateBytes);

        Assert.AreEqual("CN=helper.example.com", loaded.Subject);
        Assert.AreEqual(source.Thumbprint, loaded.Thumbprint);
        Assert.IsFalse(loaded.HasPrivateKey);
    }

    /// <summary>
    /// Tests that a PKCS#12 file is loaded including its private key.
    /// </summary>
    [TestMethod]
    public void LoadFromBytes_ReadsAPkcs12FileIncludingItsPrivateKey()
    {
        using var source = CreateCertificate();
        var certificateBytes = source.Export(X509ContentType.Pkcs12, Password);

        using var loaded = CertificateHelper.LoadFromBytes(certificateBytes, Password);

        Assert.AreEqual(source.Thumbprint, loaded.Thumbprint);
        Assert.IsTrue(loaded.HasPrivateKey);
    }

    /// <summary>
    /// Tests that a PKCS#12 file without a password is loaded, which is what the API endpoints receive.
    /// </summary>
    [TestMethod]
    public void LoadFromBytes_ReadsAPkcs12FileWithoutAPassword()
    {
        using var source = CreateCertificate();
        var certificateBytes = source.Export(X509ContentType.Pkcs12);

        using var loaded = CertificateHelper.LoadFromBytes(certificateBytes);

        Assert.AreEqual(source.Thumbprint, loaded.Thumbprint);
    }

    /// <summary>
    /// Tests that a wrong password is reported instead of being swallowed.
    /// </summary>
    [TestMethod]
    public void LoadFromBytes_ThrowsOnAWrongPassword()
    {
        using var source = CreateCertificate();
        var certificateBytes = source.Export(X509ContentType.Pkcs12, Password);

        Assert.ThrowsExactly<CryptographicException>(() => CertificateHelper.LoadFromBytes(certificateBytes, "WrongPassword"));
    }

    /// <summary>
    /// Tests that data which is no certificate at all is reported.
    /// </summary>
    [TestMethod]
    public void LoadFromBytes_ThrowsOnDataThatIsNoCertificate()
    {
        Assert.ThrowsExactly<CryptographicException>(() => CertificateHelper.LoadFromBytes([1, 2, 3, 4]));
    }
}
