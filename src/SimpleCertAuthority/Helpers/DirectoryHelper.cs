// --------------------------------------------------------------------------------------------------------------------
// <copyright file="DirectoryHelper.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The directory helper.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SimpleCertAuthority.Helpers;

/// <summary>
/// The directory helper.
/// </summary>
public static class DirectoryHelper
{
    /// <summary>
    /// Creates a directory if it does not exist.
    /// </summary>
    /// <param name="path">The path.</param>
    public static void CreateDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            Directory.CreateDirectory(path);
        }
    }
}
