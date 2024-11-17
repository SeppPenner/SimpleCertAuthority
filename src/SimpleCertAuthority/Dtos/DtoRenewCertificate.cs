// --------------------------------------------------------------------------------------------------------------------
// <copyright file="DtoRenewCertificate.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The DTO class renew the certificate.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Dtos;

/// <summary>
/// The DTO class renew the certificate.
/// </summary>
public sealed record DtoRenewCertificate
{
    /// <summary>
    /// Gets or sets the certificate bytes.
    /// </summary>
    [JsonPropertyName("CertificateBytes")]
    public byte[] CertificateBytes { get; init; } = [];

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
    /// Gets or sets the certificate password.
    /// </summary>
    [JsonPropertyName("CertificatePassword")]
    public string? CertificatePassword { get; init; }
}
