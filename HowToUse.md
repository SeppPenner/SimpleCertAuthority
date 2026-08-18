## Basic usage

### JSON configuration (Adjust this to your needs)

The name of the configuration section has to match the assembly name, so it stays
`SimpleCertAuthority`.

```json
{
    "AllowedHosts": "*",
    "SimpleCertAuthority": {
        "RootCaPassword": "Mane",
        "RootCaSubject": "CN=SimpleCertAuthorityRoot",
        "SubCaPassword": "Mane",
        "SubCaSubject": "CN=SimpleCertAuthoritySubCa",
        "DelayInMilliSeconds": 30000,
        "JsonWebTokenConfigurationKey": "jCREn#FfpP9Wv6cCZc#pQf+kuthDKW8WM/SEXn9U",
        "Users": [
            {
                "UserName": "manfred",
                "Password": "beer"
            }
        ]
    }
}
```

| Setting | Meaning |
| --- | --- |
| `RootCaPassword` | Protects the `RootCertificates/root_ca_{n}.pfx` files. |
| `RootCaSubject` | The subject of the root certificate. A leading `CN=` is optional. |
| `SubCaPassword` | Protects the `SubCaCertificates/sub_ca_{n}.pfx` files. |
| `SubCaSubject` | The subject of the sub CA certificate. A leading `CN=` is optional. |
| `DelayInMilliSeconds` | The interval of the heartbeat log message. |
| `JsonWebTokenConfigurationKey` | The signing key of the JSON web tokens, at least 32 characters. |
| `Users` | The users allowed to log in. At least one is required. |

The values shipped in `appsettings.json` are meant for a local try out. **Change the passwords, the
token key and the users before you run this anywhere else**, they are public in this repository.

The service refuses to start when a setting is missing: an empty password, an empty subject, a token
key shorter than 32 characters or an empty user list all abort the start with an explanatory
exception.

### Files created at runtime

All four directories are created relative to the **working directory** of the process, so start the
service with its working directory set to where the certification authority should live.

| Directory | Content |
| --- | --- |
| `Keys` | The RSA key pair of the root certification authority. |
| `RootCertificates` | `root_ca_{n}.pfx`, protected with `RootCaPassword`. |
| `SubCaCertificates` | `sub_ca_{n}.pfx`, protected with `SubCaPassword`. |
| `RevokedCertificates` | `revoked_certificates.json`, the revoked serial numbers. |

None of this belongs in a repository, it contains the private keys of the certification authority.

### Run the project from the command line (Examples for Powershell, but should work in other shells as well)

1. Publish the project

    ```bash
    dotnet publish src/SimpleCertAuthority/SimpleCertAuthority.csproj -c Release --output publish/
    ```

2. Run it, with the working directory set to the published output

    ```powershell
    $env:ASPNETCORE_URLS = 'http://127.0.0.1:5080'
    Start-Process -FilePath .\publish\SimpleCertAuthority.exe -WorkingDirectory .\publish
    ```

    On the first start the log reports the three creation steps:

    ```text
    [WRN] RSA key pair not loaded, creating a new one
    [WRN] No root certificate loaded, creating a new one
    [WRN] No sub CA certificate loaded, creating a new one
    ```

    On every later start these warnings must be gone. If they come back, the service did not find
    its state and is about to build a second certification authority next to the first one.

### Install it as a service

The same executable hosts itself as a Windows service and under systemd, no separate build is
needed.

1. Windows, from an elevated prompt. `binPath` has to be the published executable, and the service
   runs with the directory of the executable as its working directory:

    ```powershell
    New-Service -Name SimpleCertAuthority -BinaryPathName "C:\SimpleCertAuthority\SimpleCertAuthority.exe" -StartupType Automatic
    Start-Service -Name SimpleCertAuthority
    ```

2. Linux, as `/etc/systemd/system/simplecertauthority.service`:

    ```ini
    [Unit]
    Description=SimpleCertAuthority

    [Service]
    Type=notify
    WorkingDirectory=/opt/simplecertauthority
    ExecStart=/opt/simplecertauthority/SimpleCertAuthority
    Restart=always

    [Install]
    WantedBy=multi-user.target
    ```

    ```bash
    systemctl daemon-reload
    systemctl enable --now simplecertauthority
    ```

### Use the API

The examples use `127.0.0.1:5080` and the sample user from above.

1. Get a token. Everything below except step 2 needs it, the token is valid for 120 minutes and goes
   into an `Authorization: Bearer` header.

    ```powershell
    $token = Invoke-RestMethod -Uri 'http://127.0.0.1:5080/api/Login/login' -Method Post `
        -ContentType 'application/json' -Body (@{ UserName = 'manfred'; Password = 'beer' } | ConvertTo-Json)
    ```

2. Download the root certificates, so that the CA can be trusted by a client.

    ```powershell
    Invoke-WebRequest -Uri 'http://127.0.0.1:5080/api/Certificate/getRootCertificates' -OutFile roots.zip
    ```

3. Issue a certificate. The answer is a PKCS#12 file that contains the private key, protected with
   `CertificatePassword`.

    ```powershell
    $body = @{
        SubjectName = 'test.example.com'
        ValidFrom = (Get-Date).ToString('o')
        ValidTo = (Get-Date).AddYears(1).ToString('o')
        SanDomains = @('test.example.com', 'www.test.example.com')
        CertificatePassword = 'TestPassword'
    } | ConvertTo-Json

    Invoke-WebRequest -Uri 'http://127.0.0.1:5080/api/Certificate/generateCertificate' -Method Post `
        -Headers @{ Authorization = "Bearer $token" } `
        -ContentType 'application/json' -Body $body -OutFile certificate.pfx
    ```

4. Verify a certificate. The body is the raw certificate as a base 64 string, either the plain
   certificate or a PKCS#12 file without a password.

    ```powershell
    $cer = [Convert]::ToBase64String([IO.File]::ReadAllBytes('certificate.cer'))
    Invoke-RestMethod -Uri 'http://127.0.0.1:5080/api/Certificate/verifyCertificate' -Method Post `
        -Headers @{ Authorization = "Bearer $token" } `
        -ContentType 'application/json' -Body (ConvertTo-Json $cer)
    ```

    A valid certificate answers `200` with `Certificate verified.`, an invalid one `409` with the
    reason, for example `The certificate is revoked.`

5. Renew a certificate. The successor keeps the subject and the extensions and gets a new key pair,
   a new serial number and the new validity.

    ```powershell
    $body = @{
        CertificateBytes = $cer
        ValidFrom = (Get-Date).ToString('o')
        ValidTo = (Get-Date).AddYears(2).ToString('o')
        CertificatePassword = 'TestPassword'
    } | ConvertTo-Json

    Invoke-WebRequest -Uri 'http://127.0.0.1:5080/api/Certificate/renewCertificate' -Method Post `
        -Headers @{ Authorization = "Bearer $token" } `
        -ContentType 'application/json' -Body $body -OutFile renewed.pfx
    ```

6. Revoke a certificate. Only the serial number is stored, so the certificate itself is enough.

    ```powershell
    Invoke-RestMethod -Uri 'http://127.0.0.1:5080/api/Certificate/revokeCertificate' -Method Post `
        -Headers @{ Authorization = "Bearer $token" } `
        -ContentType 'application/json' -Body (ConvertTo-Json $cer)
    ```

7. Create another root or sub CA certificate. The newest certificate by expiration date is the one
   used for signing afterwards.

    ```powershell
    Invoke-RestMethod -Uri 'http://127.0.0.1:5080/api/Certificate/createSubCaCertificate' -Method Post `
        -Headers @{ Authorization = "Bearer $token" }
    ```

### Known limits

* Certificates issued before version 1.0.1.0 carry a malformed authority key identifier. The chain
  lookup cannot find their sub CA, so they can neither be verified nor renewed. Issue them again.
* Revocation is a plain list of serial numbers. There is no signed certificate revocation list and
  no OCSP responder, clients have to ask the API.
* The three read endpoints, the root certificates, the sub CA certificates and the revoked serial
  numbers, are open without a token, because a client needs the trust anchor and the revocation list
  before it can log in. They contain public material only. Everything else answers `401` without a
  valid token.
