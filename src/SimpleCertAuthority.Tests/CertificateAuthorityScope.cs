// --------------------------------------------------------------------------------------------------------------------
// <copyright file="CertificateAuthorityScope.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   An empty certification authority in a temporary directory.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Tests;

/// <summary>
/// An empty certification authority in a temporary directory.
/// </summary>
/// <remarks>
/// The directory names in <see cref="DirectoryNames"/> are relative, so the working directory decides
/// where the certification authority lives. Every test gets its own directory and an empty
/// <see cref="CertificateStore"/>, and leaves nothing behind. Mind that the working directory is process
/// wide, so the tests must not run in parallel.
/// </remarks>
internal sealed class CertificateAuthorityScope : IDisposable
{
    /// <summary>
    /// The working directory of the test run before this scope was entered.
    /// </summary>
    private readonly string previousWorkingDirectory;

    /// <summary>
    /// Gets the directory of this certification authority.
    /// </summary>
    public string DirectoryPath { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateAuthorityScope"/> class.
    /// </summary>
    public CertificateAuthorityScope()
    {
        this.previousWorkingDirectory = Directory.GetCurrentDirectory();
        this.DirectoryPath = Path.Combine(Path.GetTempPath(), $"SimpleCertAuthorityTests_{Guid.NewGuid():N}");

        Directory.CreateDirectory(this.DirectoryPath);
        Directory.SetCurrentDirectory(this.DirectoryPath);

        Directory.CreateDirectory(DirectoryNames.RootCertificates);
        Directory.CreateDirectory(DirectoryNames.SubCaCertificates);
        Directory.CreateDirectory(DirectoryNames.RevokedCertificates);

        CertificateStore.Clear();
    }

    /// <summary>
    /// Gets the full path of a file below this certification authority.
    /// </summary>
    /// <param name="parts">The path parts.</param>
    /// <returns>The full path.</returns>
    public string GetPath(params string[] parts)
    {
        return Path.Combine([this.DirectoryPath, .. parts]);
    }

    /// <inheritdoc cref="IDisposable"/>
    public void Dispose()
    {
        CertificateStore.Clear();
        Directory.SetCurrentDirectory(this.previousWorkingDirectory);

        try
        {
            Directory.Delete(this.DirectoryPath, true);
        }
        catch (IOException)
        {
            // A leftover directory in the temporary folder must not fail a test.
        }
    }
}
