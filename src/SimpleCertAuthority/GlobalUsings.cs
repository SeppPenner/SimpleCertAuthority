#pragma warning disable IDE0065 // Die using-Anweisung wurde falsch platziert.
global using System;
global using System.IO;
global using System.IO.Compression;
global using System.Reflection;
global using System.Security.Claims;
global using System.Security.Cryptography;
global using System.Security.Cryptography.X509Certificates;
global using System.Text;
global using System.Text.Json;
global using System.Text.Json.Serialization;

global using Microsoft.AspNetCore.Authentication.JwtBearer;
global using Microsoft.AspNetCore.Authorization;
global using Microsoft.AspNetCore.Mvc;
global using Microsoft.IdentityModel.JsonWebTokens;
global using Microsoft.IdentityModel.Tokens;

global using NSwag;
global using NSwag.Annotations;
global using NSwag.Generation.Processors.Security;

global using Serilog;
global using Serilog.Core;
global using Serilog.Events;
global using Serilog.Exceptions;

global using SimpleCertAuthority.Constants;
global using SimpleCertAuthority.Dtos;
global using SimpleCertAuthority.Helpers;

global using ILogger = Serilog.ILogger;
#pragma warning restore IDE0065 // Die using-Anweisung wurde falsch platziert.