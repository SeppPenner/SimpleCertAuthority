// --------------------------------------------------------------------------------------------------------------------
// <copyright file="SimpleCertAuthorityUser.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   A user allowed to log in, read from the configuration file.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority;

/// <summary>
/// A user allowed to log in, read from the configuration file.
/// </summary>
public sealed class SimpleCertAuthorityUser
{
    /// <summary>
    /// Gets or sets the user name.
    /// </summary>
    public string UserName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the password.
    /// </summary>
    public string Password { get; set; } = string.Empty;
}
