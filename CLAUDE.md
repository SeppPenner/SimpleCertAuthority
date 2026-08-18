# Project rules for Claude

## What this is

SimpleCertAuthority is a small ASP.NET Core web service that acts as a certification authority: it
keeps a root CA and a sub CA on disk and issues, verifies, renews and revokes certificates over a
REST API. It is an application, **not** a library and **not** a NuGet package: no
`GeneratePackageOnBuild`, no push script, no installer.

One solution `src/SimpleCertAuthority.sln` with exactly two projects:

- `src/SimpleCertAuthority/SimpleCertAuthority.csproj`, SDK `Microsoft.NET.Sdk.Web`, `OutputType`
  `Exe`, the service itself. It hosts itself as a Windows service (`UseWindowsService`) and under
  systemd (`UseSystemd`), so the same binary runs on both.
- `src/SimpleCertAuthority.Tests/SimpleCertAuthority.Tests.csproj`, MSTest, added in version 1.0.3.0.

Layout inside `src/SimpleCertAuthority`:

- `Program.cs`: reads the configuration, sets up Serilog, builds the host. `Startup.cs`: JWT bearer
  authentication, MVC, the NSwag OpenAPI document and the registration of the background service.
- `SimpleCertAuthorityService.cs`: a `BackgroundService`. Everything that matters happens in
  `StartAsync`, which creates the three state directories, loads or creates the root certificate and
  the sub CA certificate and loads the revoked serial numbers. `ExecuteAsync` only logs a heartbeat
  with memory numbers.
- `SimpleCertAuthorityConfiguration.cs` plus `SimpleCertAuthorityUser.cs`: the configuration read
  from `appsettings.json`, including the users allowed to log in. `IsValid` checks it.
- `CertificateController.cs`: the API under `api/Certificate`, see the endpoint list below.
  `LoginController.cs`: `api/Login/login`, hands out a JSON web token valid for 120 minutes.
  `ControllerBaseExtensions.cs`: the single `InternalServerError` helper.
- `Helpers/CertificateStore.cs`: the whole certificate logic, a `static` class with `static` state.
  Its `internal Clear` exists for the tests only, the service never starts over.
  `Helpers/CertificateHelper.cs`: loads a certificate from raw bytes, dispatching on the content
  type. `Helpers/ChainResult.cs`: the result of the chain lookup. `Helpers/DirectoryHelper.cs`:
  creates a directory if it is missing.
- `Constants/`: `ContentTypes`, `DirectoryNames`, `NameConstants` (file names and search patterns),
  `OidConstants` and `LoggerConfig` (the Serilog configuration of the background service).
- `Dtos/`: `DtoLogin`, `DtoCreateCertificate`, `DtoRenewCertificate`, all `sealed record`s with
  explicit `[JsonPropertyName]`.
- `GlobalUsings.cs`: all usings of the project, including the alias `ILogger = Serilog.ILogger`.

Layout inside `src/SimpleCertAuthority.Tests`:

- `CertificateStoreTests.cs`: the certification authority end to end, one test per property that used
  to be broken. Creating a root and a sub CA, loading them again, the subject without a doubled `CN=`,
  the own key pair per certificate, random serial numbers, the authority key identifier pointing back
  at the issuer, an issued certificate with a matching private key, the subject alternative names,
  validation, revocation including the file on disk, renewal and an independent chain build.
- `CertificateHelperTests.cs`: the content type dispatch, a plain certificate, a PKCS#12 file with and
  without a password, a wrong password and data that is no certificate.
- `SimpleCertAuthorityConfigurationTests.cs`: every rule of `IsValid`.
- `CertificateAuthorityScope.cs`: gives a test an empty certification authority in a temporary
  directory. It sets the working directory, because `DirectoryNames` are relative, and clears the
  static state of `CertificateStore`. The working directory is process wide, so **the tests must not
  run in parallel**, which is why nothing enables it.
- `TestDataProvider.cs`: the passwords, the subjects and the helpers both certificate test classes use.
- `GlobalUsings.cs`: all usings of the test project.

The API:

| Method | Route | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `api/Login/login` | anonymous | Returns a JSON web token for a configured user. |
| GET | `api/Certificate/getRootCertificates` | anonymous | All root certificates as a ZIP of `.cer` files. |
| GET | `api/Certificate/getSubCaCertificates` | anonymous | All sub CA certificates as a ZIP of `.cer` files. |
| GET | `api/Certificate/getRevokedCertificateSerialNumbers` | anonymous | The revoked serial numbers as JSON. |
| POST | `api/Certificate/createRootCertificate` | **token** | Creates another root certificate. |
| POST | `api/Certificate/createSubCaCertificate` | **token** | Creates another sub CA certificate. |
| POST | `api/Certificate/generateCertificate` | **token** | Issues a certificate, returns a PKCS#12 file. |
| POST | `api/Certificate/renewCertificate` | **token** | Issues a successor certificate, returns a PKCS#12 file. |
| POST | `api/Certificate/verifyCertificate` | **token** | 200 when valid, 409 with the reason when not. |
| POST | `api/Certificate/revokeCertificate` | **token** | Stores the serial number as revoked. |

The state on disk, created relative to the **working directory**:

- `RootCertificates/root_ca_{n}.pfx`, protected with `RootCaPassword`.
- `SubCaCertificates/sub_ca_{n}.pfx`, protected with `SubCaPassword`.
- `RevokedCertificates/revoked_certificates.json`, a JSON array of serial numbers.

Every certificate keeps its own private key inside its own PKCS#12 file, there is no key file next to
it. Versions up to 1.0.2.0 also wrote a `Keys` directory holding the key pair of the root CA. That
directory is not read and not created any more, a leftover from an earlier version is simply ignored
and can be deleted.

None of this belongs in git, `.gitignore` covers all four directory names, `Keys` included, so that
an old key cannot be committed by accident.

Repository root: `README.md`, `HowToUse.md` (the usage documentation), `Changelog.md`,
`License.txt` (MIT), `.gitignore` and `.gitattributes`. There is no `Updating.md`, no `.github`
folder, no test project and no screenshots.

## Build

```powershell
dotnet build src/SimpleCertAuthority.sln -c Release
```

```powershell
dotnet test src/SimpleCertAuthority.sln -c Release
```

- Single target framework `net10.0`, no multi-targeting, no `RuntimeIdentifiers`. Nothing in the
  code is Windows specific.
- All build properties live directly in `SimpleCertAuthority.csproj`. There is **no**
  `Directory.Build.props` in this repository.
- `TreatWarningsAsErrors` is enabled, so every warning breaks the build, NuGet warnings (`NU****`)
  from restore included. A clean build reports zero warnings, keep it that way.
- `NU1803` (HTTP source usage during restore) is the one warning suppressed via `NoWarn`. Fix
  warnings instead of extending that list. `NuGetAudit` and `NuGetAuditMode=all` are on, so a
  vulnerable transitive package fails the build too.
- Versions come from GitVersion.MsBuild out of the git tags. Never edit a version property or an
  assembly version by hand.
- Restore needs nuget.org. If unreachable private feeds are configured globally on the machine, the
  restore hangs for a while and then fails, and with `TreatWarningsAsErrors` the audit turns
  `NU1900` into an error. Then build with an explicit source:
  `dotnet build src/SimpleCertAuthority.sln --source https://api.nuget.org/v3/index.json`.
  Mind that `dotnet list package --outdated` ignores `--source` for the audit, so it keeps failing;
  query the versions over `https://api.nuget.org/v3-flatcontainer/<id>/index.json` instead.
- Tests are MSTest in the single test project `src/SimpleCertAuthority.Tests`, with the package set of
  the sibling repositories: `Microsoft.NET.Test.Sdk`, `MSTest.TestAdapter`, `MSTest.TestFramework`,
  `coverlet.collector` and `GitVersion.MsBuild`. `dotnet test` runs 29 tests in around 25 seconds. They
  need no network and no fixture outside the repository. The time goes into RSA key generation, roughly
  half a second per 4096 bit key, and that is why `KeySize` stays as it is instead of being made
  configurable for the tests. Every test works in its own directory below `Path.GetTempPath()` and
  deletes it afterwards, so a test run leaves the working tree untouched. `dotnet test` does not accept
  `--source`, so build first and then run it with `--no-build --no-restore` when a private feed gets in
  the way. Never claim a test run happened without running it.
- The tests cover the certificate logic and the configuration. They do not start the web host, so
  authentication, routing and the OpenAPI document are not covered. For a change in that area, publish
  the project and call the API:

```powershell
dotnet publish src/SimpleCertAuthority/SimpleCertAuthority.csproj -c Release -o <somewhere>
```

  Start the executable with the working directory set to that output, otherwise the state
  directories end up somewhere else. `ASPNETCORE_URLS` picks the port. Judge a run by the created
  files and by the API responses, and check that a **second** start logs no
  "not loaded, creating a new one" warning, which is the regression test for the loading path.

## Code conventions

Follow the surrounding code, it is consistent throughout every file:

- File header comment block with `<copyright file="..." company="Hämmer Electronics">` and a
  `<summary>`, then the file-scoped namespace.
- XML doc comments on every type and every member, private members included, no exceptions.
- `Nullable`, `ImplicitUsings` and `LangVersion latest` are enabled.
- New `using` directives go into `GlobalUsings.cs`, inside the existing `#pragma warning disable
  IDE0065` block, never at the top of a file. The editorconfig requires usings inside the namespace
  (`csharp_using_directive_placement=inside_namespace:warning`), which global usings cannot satisfy,
  that is what the pragma is for. Do not add other pragmas. The comment text in that block is
  German because Visual Studio generated it, leave it alone.
- Fields, properties, methods and events are always accessed with `this.` qualification
  (`dotnet_style_qualification_for_*` at severity `warning`). `CertificateStore` is static, so it
  has none of that.
- `src/.editorconfig` also enforces braces everywhere, no multiple blank lines, four spaces, CRLF,
  UTF-8, file scoped namespaces, `System` usings sorted first and `IDE0005` as warning. Analyzer
  warnings are fixed, not silenced.
- Comments explain the reason, not the line. Several comments in `CertificateStore` record why a
  step exists at all; those are load bearing, do not strip them.

## Known quirks

Do not silently "clean up" these, they are existing behaviour:

- **The configuration section is named after the assembly.** `Program.ReadConfiguration` binds
  `config.Bind(ServiceName.Name, ...)` and `Startup` binds
  `configuration.GetSection(this.serviceName.Name)`, both of which resolve to `SimpleCertAuthority`.
  Renaming the assembly silently orphans the whole configuration and the service then fails in
  `IsValid`. The section name in `appsettings.json` has to follow the assembly name.
- **The configuration is bound twice.** `Program.Configuration` is filled and never read, `Startup`
  binds its own instance and registers that one in the container. Only the `Startup` copy has any
  effect.
- **`IsValid` throws instead of returning false.** It returns `true` or throws, so the
  `if (!this.SimpleCertAuthorityConfiguration.IsValid())` in `StartAsync` can never be taken. The
  exception is the mechanism, the return value is decoration.
- **Every certificate gets its own key pair.** Root, sub CA and issued certificates each generate one
  in `CreateAndSave...` respectively `CreateCertificate`, and it travels inside the PKCS#12 file. Do
  not reintroduce a shared key: up to 1.0.2.0 all root certificates signed with the same key pair
  from a `Keys` directory, which gave them the same subject key identifier, so `createRootCertificate`
  rotated nothing and the chain lookup could not tell two roots apart. Certificates written by those
  versions still load and still work, only their shared key stays shared.
- **The state directory depends on the working directory.** `DirectoryNames` are relative, while the
  web host uses the assembly location as content root. Starting the service from a different working
  directory creates a second, empty certification authority instead of finding the existing one.
- **`CertificateStore` is static and never resets.** The loaded certificates live in static lists for
  the lifetime of the process, and the loading methods append instead of replacing. They are called
  once from `StartAsync`, calling them again would duplicate entries.
- **The certificate controller is protected by default.** `CertificateController` carries
  `[Authorize]` on the class, and only `getRootCertificates`, `getSubCaCertificates` and
  `getRevokedCertificateSerialNumbers` opt out with `[AllowAnonymous]`, because a client needs them
  before it can trust or even reach the login. A new endpoint is therefore protected unless it says
  otherwise, which is the way round that fails safe. Keep it that way, and use the
  `AspNetCoreOperationSecurityScopeProcessor` in `Startup`, not `OperationSecurityScopeProcessor`:
  only the AspNetCore variant reads the attributes, the other one marks every operation in the
  OpenAPI document as secured, including the anonymous ones.
- **Revocation is a list of serial numbers, not a CRL.** `revokeCertificate` stores
  `certificate.SerialNumber` in a JSON array, `getRevokedCertificateSerialNumbers` serves it, and
  `ValidateCertificate` checks it before it builds the chain. Nothing signs that list, and
  `AddRevokedCertificate` does not deduplicate.
- **The chain is found over the key identifiers, not over the signature.** `FindMatchingCertificates`
  matches the authority key identifier of the certificate against the subject key identifier of the
  sub CA, and then the same one level up. Certificates issued before version 1.0.1.0 carry an
  authority key identifier that was encoded by hand and is two bytes too long, so they are not found
  any more and cannot be verified or renewed.
- **`ValidateCertificate` is more lenient than the lookup in front of it.** It puts the sub CA into
  `CustomTrustStore` next to the root and sets `AllowUnknownCertificateAuthority`, and it filters
  `UntrustedRoot` out of the reported errors. The preceding chain lookup is what actually pins the
  certificate to this CA.
- **`EphemeralKeySet` for every PKCS#12 load.** `CertificateStore.KeyStorageFlags` keeps the private
  keys in memory, so that a service start does not leave a key in the platform key store. That flag
  is not supported on macOS.
- **Both download endpoints deliver `certificate.zip`.** `NameConstants.CertificatesFileName` is
  used for the root and for the sub CA download, the file name does not say which one it is.
- **`.dockerignore` without a Dockerfile.** `src/.dockerignore` is tracked, but there is no
  Dockerfile and no compose file in this repository.
- **The service name in the log is the assembly name.** `LogMemoryInformation` writes a heartbeat
  every `DelayInMilliSeconds`, which is the only thing `ExecuteAsync` does.

## Releasing

1. Make the change.
2. Add an entry at the top of `Changelog.md` in the existing format:
   `* **Version 1.0.1.0 (2026-08-17)** : Short description.`
3. Commit that.
4. Tag the commit with the plain version number, no `v` prefix (`1.0.1`, `1.0.2`, ...). Create
   lightweight tags, the same way the release before did.
5. Push the commits and the tag.

The version in `Changelog.md` has four parts (`1.0.1.0`), the tag has three (`1.0.1`). GitVersion
turns the tag into the assembly version, so an untagged commit produces something like
`1.0.2-1+Branch.main.Sha...`. Version 1.0.0.0 was never tagged, which is why the builds before
1.0.1 reported themselves as `0.0.1`. There is no installer to build and no package to push, so the
release ends with the push.

## Git

- **Never amend a commit.** No `git commit --amend`, not for a typo in the message, not to add a
  forgotten file, not even when the commit is still local. Write a follow-up commit instead. The
  release versions come from tags on exact commits, an amended commit leaves its tag pointing at a
  commit that no longer exists in the branch.
- **Never `git add -A` in this repository.** The working tree can hold a real certification authority
  under `RootCertificates/`, `SubCaCertificates/` and, from an older version, `Keys/`. All of them are
  ignored, but add files by name anyway.

## Writing style

- Commit messages are written **in English only**: short, precise subject line, explanatory body
  when needed.
- Code comments and comments in project files such as `.csproj` are **always English**, regardless
  of the language used in the conversation.
- **No em dashes or en dashes** (`—`, `–`), neither in prose, commit messages, code comments nor
  documentation. Use a regular hyphen, comma, colon, parentheses or a separate sentence.
- German texts (documentation, chat replies) always use real umlauts and ß, never ASCII
  transliterations such as `ae`, `oe`, `ue` or `ss`. Identifiers, file names and configuration keys
  stay unchanged where umlauts are technically undesirable.
