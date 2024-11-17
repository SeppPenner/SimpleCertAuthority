// --------------------------------------------------------------------------------------------------------------------
// <copyright file="DtoLogin.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The DTO class to login.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Dtos;

/// <summary>
/// The DTO class to login.
/// </summary>
public sealed record DtoLogin
{
    /// <summary>
    /// Gets or sets the user name.
    /// </summary>
    [JsonPropertyName("UserName")]
    public string UserName { get; init; } = string.Empty;

    /// <summary>
    /// Gets or sets the password.
    /// </summary>
    [JsonPropertyName("Password")]
    public string Password { get; init; } = string.Empty;
}
