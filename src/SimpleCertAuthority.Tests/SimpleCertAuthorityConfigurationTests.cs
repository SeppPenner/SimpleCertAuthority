// --------------------------------------------------------------------------------------------------------------------
// <copyright file="SimpleCertAuthorityConfigurationTests.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   Tests the <see cref="SimpleCertAuthorityConfiguration" />.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Tests;

/// <summary>
/// Tests the <see cref="SimpleCertAuthorityConfiguration"/>.
/// </summary>
[TestClass]
public sealed class SimpleCertAuthorityConfigurationTests
{
    /// <summary>
    /// Creates a configuration that passes every check.
    /// </summary>
    /// <returns>The <see cref="SimpleCertAuthorityConfiguration"/>.</returns>
    private static SimpleCertAuthorityConfiguration CreateValidConfiguration()
    {
        return new SimpleCertAuthorityConfiguration
        {
            RootCaPassword = TestDataProvider.RootCaPassword,
            RootCaSubject = TestDataProvider.RootCaSubject,
            SubCaPassword = TestDataProvider.SubCaPassword,
            SubCaSubject = TestDataProvider.SubCaSubject,
            DelayInMilliSeconds = 30000,
            JsonWebTokenConfigurationKey = new string('k', 32),
            Users = [new SimpleCertAuthorityUser { UserName = "manfred", Password = "beer" }]
        };
    }

    /// <summary>
    /// Tests that a complete configuration is accepted.
    /// </summary>
    [TestMethod]
    public void IsValid_AcceptsACompleteConfiguration()
    {
        Assert.IsTrue(CreateValidConfiguration().IsValid());
    }

    /// <summary>
    /// Tests that an empty root CA password is reported.
    /// </summary>
    [TestMethod]
    public void IsValid_ThrowsOnAnEmptyRootCaPassword()
    {
        var configuration = CreateValidConfiguration();
        configuration.RootCaPassword = string.Empty;

        var exception = Assert.ThrowsExactly<Exception>(() => configuration.IsValid());
        StringAssert.Contains(exception.Message, "root CA password is empty");
    }

    /// <summary>
    /// Tests that a delay of zero is reported.
    /// </summary>
    [TestMethod]
    public void IsValid_ThrowsOnADelayOfZero()
    {
        var configuration = CreateValidConfiguration();
        configuration.DelayInMilliSeconds = 0;

        var exception = Assert.ThrowsExactly<Exception>(() => configuration.IsValid());
        StringAssert.Contains(exception.Message, "delay in milliseconds");
    }

    /// <summary>
    /// Tests that a short token key is reported, because it would not carry HMAC SHA256.
    /// </summary>
    [TestMethod]
    public void IsValid_ThrowsOnATooShortJsonWebTokenKey()
    {
        var configuration = CreateValidConfiguration();
        configuration.JsonWebTokenConfigurationKey = new string('k', 31);

        var exception = Assert.ThrowsExactly<Exception>(() => configuration.IsValid());
        StringAssert.Contains(exception.Message, "too short");
    }

    /// <summary>
    /// Tests that a configuration without users is reported, so that the service does not start with a
    /// login nobody can pass.
    /// </summary>
    [TestMethod]
    public void IsValid_ThrowsWhenNoUserIsConfigured()
    {
        var configuration = CreateValidConfiguration();
        configuration.Users = [];

        var exception = Assert.ThrowsExactly<Exception>(() => configuration.IsValid());
        StringAssert.Contains(exception.Message, "No user is configured");
    }

    /// <summary>
    /// Tests that a user without a password is reported.
    /// </summary>
    [TestMethod]
    public void IsValid_ThrowsOnAUserWithoutAPassword()
    {
        var configuration = CreateValidConfiguration();
        configuration.Users = [new SimpleCertAuthorityUser { UserName = "manfred", Password = string.Empty }];

        var exception = Assert.ThrowsExactly<Exception>(() => configuration.IsValid());
        StringAssert.Contains(exception.Message, "password of the user manfred is empty");
    }
}
