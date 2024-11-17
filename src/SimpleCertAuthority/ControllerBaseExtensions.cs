// --------------------------------------------------------------------------------------------------------------------
// <copyright file="ControllerBaseExtensions.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The controller base extensions.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority;

/// <summary>
/// The controller base extensions.
/// </summary>
public static class ControllerBaseExtensions
{
    /// <summary>
    /// Handles the internal server error response.
    /// </summary>
    /// <param name="controller">The controller.</param>
    /// <param name="errorMessage">The error message.</param>
    /// <returns>The internal server error <see cref="ActionResult"/>.</returns>
    public static ActionResult InternalServerError(this ControllerBase controller, string errorMessage)
    {
        return controller.StatusCode(StatusCodes.Status500InternalServerError, new { errorMessage });
    }
}
