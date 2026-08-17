// --------------------------------------------------------------------------------------------------------------------
// <copyright file="CertificateHelper.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The certificate helper.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Helpers;

/// <summary>
/// The certificate helper.
/// </summary>
public static class CertificateHelper
{
    /// <summary>
    /// Loads a certificate from its raw bytes.
    /// </summary>
    /// <param name="certificateBytes">The certificate bytes.</param>
    /// <param name="password">The password of a PKCS#12 file.</param>
    /// <param name="keyStorageFlags">The key storage flags used for a PKCS#12 file.</param>
    /// <returns>The <see cref="X509Certificate2"/>.</returns>
    /// <remarks>
    /// The callers hand over either a plain certificate or a PKCS#12 file, so the content type decides
    /// which loader is used. <see cref="X509CertificateLoader"/> has no auto detecting entry point, the
    /// obsolete <see cref="X509Certificate2"/> constructors had one.
    /// </remarks>
    public static X509Certificate2 LoadFromBytes(
        byte[] certificateBytes,
        string? password = null,
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.EphemeralKeySet)
    {
        return X509Certificate2.GetCertContentType(certificateBytes) switch
        {
            X509ContentType.Pkcs12 => X509CertificateLoader.LoadPkcs12(certificateBytes, password, keyStorageFlags),
            _ => X509CertificateLoader.LoadCertificate(certificateBytes)
        };
    }
}
