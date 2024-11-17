// --------------------------------------------------------------------------------------------------------------------
// <copyright file="DirectoryNames.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The directory names.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Constants;

/// <summary>
/// The directory names.
/// </summary>
public static class DirectoryNames
{
    /// <summary>
    /// The root certificates directory.
    /// </summary>
    public const string RootCertificates = "RootCertificates";

    /// <summary>
    /// The sub CA certificates directory.
    /// </summary>
    public const string SubCaCertificates = "SubCaCertificates";

    /// <summary>
    /// The revoked certificates directory.
    /// </summary>
    public const string RevokedCertificates = "RevokedCertificates";

    /// <summary>
    /// The keys directory.
    /// </summary>
    public const string Keys = "Keys";
}
