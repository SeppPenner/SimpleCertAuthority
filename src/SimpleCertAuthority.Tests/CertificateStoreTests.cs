// --------------------------------------------------------------------------------------------------------------------
// <copyright file="CertificateStoreTests.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   Tests the <see cref="CertificateStore" />.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Tests;

/// <summary>
/// Tests the <see cref="CertificateStore"/>.
/// </summary>
[TestClass]
public sealed class CertificateStoreTests
{
    /// <summary>
    /// The certification authority of the running test.
    /// </summary>
    private CertificateAuthorityScope scope = null!;

    /// <summary>
    /// Gives the test an empty certification authority in its own directory.
    /// </summary>
    [TestInitialize]
    public void TestInitialize()
    {
        this.scope = new CertificateAuthorityScope();
    }

    /// <summary>
    /// Removes the certification authority of the test.
    /// </summary>
    [TestCleanup]
    public void TestCleanup()
    {
        this.scope.Dispose();
    }

    /// <summary>
    /// Tests that the configured subject is not prefixed twice.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task CreateAndSaveRootCertificate_StripsTheConfiguredCnPrefix()
    {
        await CertificateStore.CreateAndSaveRootCertificate(TestDataProvider.RootCaPassword, TestDataProvider.RootCaSubject);

        var rootCertificate = CertificateStore.GetRootCertificates().Single();
        Assert.AreEqual("CN=TestRootCa", rootCertificate.Subject);
        Assert.IsTrue(File.Exists(this.scope.GetPath(DirectoryNames.RootCertificates, "root_ca_1.pfx")));
    }

    /// <summary>
    /// Tests that the root certificate can sign and can be exported.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task CreateAndSaveRootCertificate_IsSelfSignedAndKeepsItsPrivateKey()
    {
        await CertificateStore.CreateAndSaveRootCertificate(TestDataProvider.RootCaPassword, TestDataProvider.RootCaSubject);

        var rootCertificate = CertificateStore.GetRootCertificates().Single();
        Assert.AreEqual(rootCertificate.Subject, rootCertificate.Issuer);
        Assert.IsTrue(rootCertificate.HasPrivateKey);
    }

    /// <summary>
    /// Tests that a second root certificate really rotates the key.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task CreateAndSaveRootCertificate_GivesEveryCertificateItsOwnKeyPair()
    {
        await CertificateStore.CreateAndSaveRootCertificate(TestDataProvider.RootCaPassword, TestDataProvider.RootCaSubject);
        await CertificateStore.CreateAndSaveRootCertificate(TestDataProvider.RootCaPassword, TestDataProvider.RootCaSubject);

        var rootCertificates = CertificateStore.GetRootCertificates();
        Assert.AreEqual(2, rootCertificates.Count);
        Assert.IsTrue(File.Exists(this.scope.GetPath(DirectoryNames.RootCertificates, "root_ca_2.pfx")));

        // A shared key pair would produce the same public key and therefore the same subject key
        // identifier, which the chain lookup could not tell apart.
        Assert.AreNotEqual(
            TestDataProvider.GetPublicKey(rootCertificates[0]),
            TestDataProvider.GetPublicKey(rootCertificates[1]));
        Assert.AreNotEqual(
            TestDataProvider.GetSubjectKeyIdentifier(rootCertificates[0]),
            TestDataProvider.GetSubjectKeyIdentifier(rootCertificates[1]));
        Assert.AreNotEqual(rootCertificates[0].SerialNumber, rootCertificates[1].SerialNumber);
    }

    /// <summary>
    /// Tests that a written root certificate is found again with its private key.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task LoadRootCertificates_ReadsTheWrittenCertificateIncludingItsPrivateKey()
    {
        await CertificateStore.CreateAndSaveRootCertificate(TestDataProvider.RootCaPassword, TestDataProvider.RootCaSubject);
        var thumbprint = CertificateStore.GetRootCertificates().Single().Thumbprint;

        // Start over, as a restart of the service would.
        CertificateStore.Clear();
        var numberOfRootCertificates = await CertificateStore.LoadRootCertificates(TestDataProvider.RootCaPassword);

        Assert.AreEqual(1, numberOfRootCertificates);
        var loaded = CertificateStore.GetRootCertificates().Single();
        Assert.AreEqual(thumbprint, loaded.Thumbprint);
        Assert.IsTrue(loaded.HasPrivateKey);
    }

    /// <summary>
    /// Tests that the sub CA certificate is signed by the root and points back to it.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task CreateAndSaveSubCaCertificate_IsSignedByTheRootAndPointsBackToIt()
    {
        await TestDataProvider.CreateCertificationAuthority();

        var rootCertificate = CertificateStore.GetRootCertificates().Single();
        var subCaCertificate = CertificateStore.GetSubCaCertificates().Single();

        Assert.AreEqual("CN=TestSubCa", subCaCertificate.Subject);
        Assert.AreEqual(rootCertificate.Subject, subCaCertificate.Issuer);
        Assert.IsTrue(subCaCertificate.HasPrivateKey);

        // Without this the chain lookup cannot get from the sub CA certificate to its root certificate.
        Assert.AreEqual(
            TestDataProvider.GetSubjectKeyIdentifier(rootCertificate),
            TestDataProvider.GetAuthorityKeyIdentifier(subCaCertificate));
    }

    /// <summary>
    /// Tests that sub CA certificates do not share a serial number.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task CreateAndSaveSubCaCertificate_UsesARandomSerialNumber()
    {
        await TestDataProvider.CreateCertificationAuthority();
        await CertificateStore.CreateAndSaveSubCaCertificate(TestDataProvider.SubCaPassword, TestDataProvider.SubCaSubject);

        var subCaCertificates = CertificateStore.GetSubCaCertificates();
        Assert.AreEqual(2, subCaCertificates.Count);
        Assert.AreNotEqual(subCaCertificates[0].SerialNumber, subCaCertificates[1].SerialNumber);
    }

    /// <summary>
    /// Tests that a missing root certificate is reported.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task CreateAndSaveSubCaCertificate_ThrowsWithoutARootCertificate()
    {
        var exception = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => CertificateStore.CreateAndSaveSubCaCertificate(TestDataProvider.SubCaPassword, TestDataProvider.SubCaSubject));

        StringAssert.Contains(exception.Message, "Root certificate is missing");
    }

    /// <summary>
    /// Tests that an issued certificate carries a usable private key.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task CreateCertificate_ReturnsACertificateWithAMatchingPrivateKey()
    {
        await TestDataProvider.CreateCertificationAuthority();

        using var certificate = TestDataProvider.IssueCertificate();

        Assert.AreEqual("CN=test.example.com", certificate.Subject);
        Assert.AreEqual("CN=TestSubCa", certificate.Issuer);
        Assert.IsTrue(certificate.HasPrivateKey);

        // The key has to belong to the certificate, otherwise the delivered PKCS#12 file is useless.
        using var privateKey = certificate.GetRSAPrivateKey();
        using var publicKey = certificate.GetRSAPublicKey();
        Assert.IsNotNull(privateKey);
        Assert.IsNotNull(publicKey);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.IsTrue(publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    /// <summary>
    /// Tests that no key of a certification authority is handed out.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task CreateCertificate_DoesNotHandOutTheKeyOfACertificationAuthority()
    {
        await TestDataProvider.CreateCertificationAuthority();

        using var first = TestDataProvider.IssueCertificate("first.example.com");
        using var second = TestDataProvider.IssueCertificate("second.example.com");

        var rootKey = TestDataProvider.GetPublicKey(CertificateStore.GetRootCertificates().Single());
        var subCaKey = TestDataProvider.GetPublicKey(CertificateStore.GetSubCaCertificates().Single());
        var firstKey = TestDataProvider.GetPublicKey(first);
        var secondKey = TestDataProvider.GetPublicKey(second);

        Assert.AreNotEqual(rootKey, firstKey);
        Assert.AreNotEqual(subCaKey, firstKey);
        Assert.AreNotEqual(rootKey, subCaKey);
        Assert.AreNotEqual(firstKey, secondKey);
    }

    /// <summary>
    /// Tests that the subject alternative names reach the certificate.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task CreateCertificate_AddsTheSubjectAlternativeNames()
    {
        await TestDataProvider.CreateCertificationAuthority();

        using var certificate = TestDataProvider.IssueCertificate("test.example.com", "test.example.com", "www.test.example.com");

        var extension = certificate.Extensions[OidConstants.SubjectAlternativeName];
        Assert.IsNotNull(extension);
        var subjectAlternativeNames = new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);
        var dnsNames = subjectAlternativeNames.EnumerateDnsNames().ToList();
        Assert.AreEqual(2, dnsNames.Count);
        Assert.IsTrue(dnsNames.Contains("test.example.com"));
        Assert.IsTrue(dnsNames.Contains("www.test.example.com"));
    }

    /// <summary>
    /// Tests that an inverted validity is rejected.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task CreateCertificate_ThrowsWhenTheValidityIsInverted()
    {
        await TestDataProvider.CreateCertificationAuthority();

        var exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => CertificateStore.CreateCertificate(
                "test.example.com",
                DateTimeOffset.UtcNow.AddYears(1),
                DateTimeOffset.UtcNow,
                []));

        StringAssert.Contains(exception.Message, "valid from date must be before");
    }

    /// <summary>
    /// Tests that a missing sub CA certificate is reported.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task CreateCertificate_ThrowsWithoutASubCaCertificate()
    {
        await CertificateStore.CreateAndSaveRootCertificate(TestDataProvider.RootCaPassword, TestDataProvider.RootCaSubject);

        var exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => TestDataProvider.IssueCertificate());

        StringAssert.Contains(exception.Message, "Sub CA certificate is missing");
    }

    /// <summary>
    /// Tests that a freshly issued certificate is accepted.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task ValidateCertificate_AcceptsAFreshlyIssuedCertificate()
    {
        await TestDataProvider.CreateCertificationAuthority();
        using var certificate = TestDataProvider.IssueCertificate();

        var isValid = CertificateStore.ValidateCertificate(certificate, out var validationError);

        Assert.IsTrue(isValid, validationError);
        Assert.AreEqual(string.Empty, validationError);
    }

    /// <summary>
    /// Tests that a certificate of a foreign certification authority is rejected.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task ValidateCertificate_RejectsACertificateOfAForeignAuthority()
    {
        await TestDataProvider.CreateCertificationAuthority();

        // A self-signed certificate that this certification authority never issued.
        using var foreignKey = RSA.Create(2048);
        var request = new CertificateRequest("CN=foreign.example.com", foreignKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var foreignCertificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var isValid = CertificateStore.ValidateCertificate(foreignCertificate, out var validationError);

        Assert.IsFalse(isValid);
        StringAssert.Contains(validationError, "authority key identifier");
    }

    /// <summary>
    /// Tests that a revoked certificate is rejected and that the serial number survives a restart.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task AddRevokedCertificate_IsPersistedAndRejectsTheCertificate()
    {
        await TestDataProvider.CreateCertificationAuthority();
        using var certificate = TestDataProvider.IssueCertificate();
        Assert.IsTrue(CertificateStore.ValidateCertificate(certificate, out _));

        await CertificateStore.AddRevokedCertificate(certificate.SerialNumber);

        var isValid = CertificateStore.ValidateCertificate(certificate, out var validationError);
        Assert.IsFalse(isValid);
        Assert.AreEqual("The certificate is revoked.", validationError);

        // The serial number has to be on disk, otherwise a restart forgets the revocation.
        var revokedFile = this.scope.GetPath(DirectoryNames.RevokedCertificates, "revoked_certificates.json");
        Assert.IsTrue(File.Exists(revokedFile));
        var persisted = JsonSerializer.Deserialize<List<string>>(await File.ReadAllBytesAsync(revokedFile));
        Assert.IsNotNull(persisted);
        Assert.IsTrue(persisted.Contains(certificate.SerialNumber));

        CertificateStore.Clear();
        await CertificateStore.LoadRevokedCertificates();
        Assert.IsTrue(CertificateStore.GetRevokedCertificateSerialNumbers().Contains(certificate.SerialNumber));
    }

    /// <summary>
    /// Tests that a renewed certificate names the signing sub CA as its issuer.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task RenewCertificate_NamesTheSubCaAsIssuer()
    {
        await TestDataProvider.CreateCertificationAuthority();
        using var certificate = TestDataProvider.IssueCertificate();

        using var renewed = CertificateStore.RenewCertificate(
            certificate,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(2));

        Assert.AreEqual(certificate.Subject, renewed.Subject);
        Assert.AreEqual("CN=TestSubCa", renewed.Issuer);
        Assert.IsTrue(renewed.HasPrivateKey);
        Assert.AreNotEqual(certificate.SerialNumber, renewed.SerialNumber);
        Assert.AreNotEqual(TestDataProvider.GetPublicKey(certificate), TestDataProvider.GetPublicKey(renewed));
        Assert.IsTrue(CertificateStore.ValidateCertificate(renewed, out var validationError), validationError);
    }

    /// <summary>
    /// Tests that an expired certificate is not renewed.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    [TestMethod]
    public async Task RenewCertificate_ThrowsForAnExpiredCertificate()
    {
        await TestDataProvider.CreateCertificationAuthority();
        using var expired = CertificateStore.CreateCertificate(
            "expired.example.com",
            DateTimeOffset.UtcNow.AddDays(-2),
            DateTimeOffset.UtcNow.AddSeconds(-1),
            []);

        var exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => CertificateStore.RenewCertificate(
                expired,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddYears(1)));

        StringAssert.Contains(exception.Message, "already expired");
    }

    /// <summary>
    /// Tests that an issued certificate chains up to the root certificate.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing any asynchronous operation.</returns>
    /// <remarks>
    /// This builds the chain without the relaxations <see cref="CertificateStore.ValidateCertificate"/>
    /// applies, so it checks the signatures instead of the key identifiers.
    /// </remarks>
    [TestMethod]
    public async Task IssuedCertificate_ChainsUpToTheRootCertificate()
    {
        await TestDataProvider.CreateCertificationAuthority();
        using var certificate = TestDataProvider.IssueCertificate();

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(CertificateStore.GetRootCertificates().Single());
        chain.ChainPolicy.ExtraStore.Add(CertificateStore.GetSubCaCertificates().Single());

        var isValid = chain.Build(certificate);

        var status = string.Join(", ", chain.ChainStatus.Select(entry => entry.Status));
        Assert.IsTrue(isValid, status);
        Assert.AreEqual(3, chain.ChainElements.Count);
        Assert.AreEqual(0, chain.ChainStatus.Length);
    }
}
