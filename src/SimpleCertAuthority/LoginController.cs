// --------------------------------------------------------------------------------------------------------------------
// <copyright file="LoginController.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The login controller.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority;

/// <summary>
/// The login controller.
/// </summary>
[Route("api/[controller]")]
[ApiController]
[OpenApiTag("Login", Description = "Login management.")]
public sealed class LoginController : ControllerBase
{
    /// <summary>
    /// The token handler.
    /// </summary>
    private readonly JsonWebTokenHandler TokenHandler = new();

    /// <summary>
    /// The simple cert authority configuration.
    /// </summary>
    private readonly SimpleCertAuthorityConfiguration simpleCertAuthorityConfiguration;

    /// <summary>
    /// Initializes a new instance of the <see cref="LoginController"/> class.
    /// </summary>
    /// <param name="simpleCertAuthorityConfiguration">The simple cert authority configuration.</param>
    public LoginController(SimpleCertAuthorityConfiguration simpleCertAuthorityConfiguration)
    {
        this.simpleCertAuthorityConfiguration = simpleCertAuthorityConfiguration;
    }

    /// <summary>
    /// Does a user login
    /// </summary>
    /// <param name="dtoLogin">The DTO to login.</param>
    /// <returns>
    /// Returns the token.
    /// </returns>
    /// <remarks>
    /// Does a user login.
    /// </remarks>
    /// <response code="200">Login valid.</response>
    /// <response code="400">Bad request.</response>
    /// <response code="401">Unauthorized.</response>
    /// <response code="500">Internal server error.</response>
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(string), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(string), StatusCodes.Status500InternalServerError)]
    [HttpPost("login")]
    [AllowAnonymous]
    public ActionResult<string> LogIn(DtoLogin dtoLogin)
    {
        if (string.IsNullOrWhiteSpace(dtoLogin.UserName))
        {
            return this.BadRequest("The user name is not set");
        }

        if (string.IsNullOrWhiteSpace(dtoLogin.Password))
        {
            return this.BadRequest("The password is not set");
        }

        if (dtoLogin.UserName == "manfred" && dtoLogin.Password == "beer")
        {
            var token = this.GenerateToken(dtoLogin.UserName);
            return this.Ok(token);
        }

        return this.Unauthorized();
    }

    /// <summary>
    /// Generates a JSON web token for the user.
    /// </summary>
    /// <param name="userName">The user name.</param>
    /// <returns>The JSON web token with a base 64 <see cref="string"/>.</returns>
    private string GenerateToken(string userName)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(this.simpleCertAuthorityConfiguration.JsonWebTokenConfigurationKey));

        var claims = new List<Claim>()
        {
            new(ClaimTypes.Name, userName)
        };

        var securityClaims = claims.ToDictionary(c => c.Type, c => (object)c.Value);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "SimpleCertAuthorityIssuer",
            Audience = "SimpleCertAuthorityAudience",
            Claims = securityClaims,
            IssuedAt = null,
            NotBefore = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddMinutes(120),
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature)
        };

        return this.TokenHandler.CreateToken(descriptor);
    }
}
