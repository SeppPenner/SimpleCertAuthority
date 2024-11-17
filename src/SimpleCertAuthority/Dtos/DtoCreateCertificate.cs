// --------------------------------------------------------------------------------------------------------------------
// <copyright file="DtoCreateCertificate.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The DTO class to create a certificate.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Dtos;

/// <summary>
/// The DTO class to create a certificate.
/// </summary>
public sealed record DtoCreateCertificate
{
    /// <summary>
    /// Gets or sets the subject name.
    /// </summary>
    [JsonPropertyName("SubjectName")]
    public string SubjectName { get; init; } = string.Empty;

    /// <summary>
    /// Gets or sets the valid from timestamp.
    /// </summary>
    [JsonPropertyName("ValidFrom")]
    public DateTimeOffset ValidFrom { get; init; }

    /// <summary>
    /// Gets or sets the valid to timestamp.
    /// </summary>
    [JsonPropertyName("ValidTo")]
    public DateTimeOffset ValidTo { get; init; }

    /// <summary>
    /// Gets or sets the SAN domains.
    /// </summary>
    [JsonPropertyName("SanDomains")]
    public string[] SanDomains { get; init; } = [];

    /// <summary>
    /// Gets or sets the certificate password.
    /// </summary>
    [JsonPropertyName("CertificatePassword")]
    public string? CertificatePassword { get; init; }
}
