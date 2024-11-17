// --------------------------------------------------------------------------------------------------------------------
// <copyright file="OidConstants.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The OID constants.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Constants;

/// <summary>
/// The OID constants.
/// </summary>
public static class OidConstants
{
    /// <summary>
    /// The server authentication OID.
    /// </summary>
    public const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";

    /// <summary>
    /// The subject key identifier OID.
    /// </summary>
    public const string SubjectKeyIdentifier = "2.5.29.14";

    /// <summary>
    /// The authority key identifier OID.
    /// </summary>
    public const string AuthorityKeyIdentifier = "2.5.29.35";

    /// <summary>
    /// The subject alternative name OID.
    /// </summary>
    public const string SubjectAlternativeName = "2.5.29.17";

    /// <summary>
    /// The basic constraints OID.
    /// </summary>
    public const string BasicConstraints = "2.5.29.19";

    /// <summary>
    /// The key usage OID.
    /// </summary>
    public const string KeyUsage = "2.5.29.15";

    /// <summary>
    /// The extended key usage OID.
    /// </summary>
    public const string EnhancedKeyUsage = "2.5.29.37";
}
