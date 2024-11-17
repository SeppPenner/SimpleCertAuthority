// --------------------------------------------------------------------------------------------------------------------
// <copyright file="SimpleCertAuthorityConfiguration.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The <see cref="SimpleCertAuthorityConfiguration" /> read from the configuration file.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority;

/// <summary>
/// The <see cref="SimpleCertAuthorityConfiguration" /> read from the configuration file.
/// </summary>
public sealed class SimpleCertAuthorityConfiguration
{
    /// <summary>
    /// Gets or sets the root CA password.
    /// </summary>
    public string RootCaPassword { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the root CA subject.
    /// </summary>
    public string RootCaSubject { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the sub CA password.
    /// </summary>
    public string SubCaPassword { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the sub CA subject.
    /// </summary>
    public string SubCaSubject { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the service delay in milliseconds.
    /// </summary>
    public int DelayInMilliSeconds { get; set; } = 1000;

    /// <summary>
    /// Gets or sets the JSON WebToken configuration key.
    /// </summary>
    public string JsonWebTokenConfigurationKey { get; set; } = string.Empty;

    /// <summary>
    /// Checks whether the configuration is valid or not.
    /// </summary>
    /// <returns>A value indicating whether the configuration is valid or not.</returns>
    public bool IsValid()
    {
        if (string.IsNullOrWhiteSpace(this.RootCaPassword))
        {
            throw new Exception("The root CA password is empty.");
        }

        if (string.IsNullOrWhiteSpace(this.RootCaSubject))
        {
            throw new Exception("The root CA subject is empty.");
        }

        if (string.IsNullOrWhiteSpace(this.SubCaPassword))
        {
            throw new Exception("The sub CA password is empty.");
        }

        if (string.IsNullOrWhiteSpace(this.SubCaSubject))
        {
            throw new Exception("The sub CA subject is empty.");
        }

        if (this.DelayInMilliSeconds <= 0)
        {
            throw new Exception("The delay in milliseconds is less than or equal to zero.");
        }

        if (string.IsNullOrWhiteSpace(this.JsonWebTokenConfigurationKey))
        {
            throw new Exception("The JSON WebToken configuration key is empty.");
        }

        if (this.JsonWebTokenConfigurationKey.Length < 32)
        {
            throw new Exception("The JSON WebToken configuration key is too short.");
        }

        return true;
    }
}
