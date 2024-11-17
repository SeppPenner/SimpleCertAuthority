// --------------------------------------------------------------------------------------------------------------------
// <copyright file="NameConstants.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The name constants.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Constants;

/// <summary>
/// The name constants.
/// </summary>
public static class NameConstants
{
    /// <summary>
    /// The file name of the RSA private key.
    /// </summary>
    public const string PrivateKeyFileName = "rsa_private_key.pem";

    /// <summary>
    /// The file name of the RSA public key.
    /// </summary>
    public const string PublicKeyFileName = "rsa_public_key.pem";

    /// <summary>
    /// The file name of the root certificate.
    /// </summary>
    public const string RootCertificateFileName = "root_ca_{0}.pfx";

    /// <summary>
    /// The file name of the SubCa certificate.
    /// </summary>
    public const string SubCaCertificateFileName = "sub_ca_{0}.pfx";

    /// <summary>
    /// The file name of the revoked certificates.
    /// </summary>
    public const string RevokedCertificatesFileName = "revoked_certificates.json";

    /// <summary>
    /// The certificate file name.
    /// </summary>
    public const string CertificateFileName = "certificate.pfx";

    /// <summary>
    /// The certificate files name.
    /// </summary>
    public const string CertificatesFileName = "certificate.zip";
}
