// --------------------------------------------------------------------------------------------------------------------
// <copyright file="ChainResult.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The chain result.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Helpers;

/// <summary>
/// The chain result.
/// </summary>
public sealed record ChainResult
{
    /// <summary>
    /// Gets or sets the sub CA certificate.
    /// </summary>
    public X509Certificate2? SubCaCertificate { get; set; }

    /// <summary>
    /// Gets or sets the root certificate.
    /// </summary>
    public X509Certificate2? RootCertificate { get; set; }

    /// <summary>
    /// Gets or sets the error message.
    /// </summary>
    public string ErrorMessage { get; set; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether the chain is complete or not.
    /// </summary>
    public bool IsComplete => this.SubCaCertificate is not null && this.RootCertificate is not null;
}
