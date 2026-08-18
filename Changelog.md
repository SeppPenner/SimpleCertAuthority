# Change history

* **Version 1.0.2.0 (2026-08-18)** : Issuing, verifying, renewing and revoking a certificate requires a token now, the certificate controller is authorized by default and only the root certificate, sub CA certificate and revoked serial number downloads stay anonymous.
* **Version 1.0.1.0 (2026-08-17)** : Fixed the build, fixed the certificate handling (Root CA subject, sub CA and issued certificate private keys, authority key identifier, issuer of a renewed certificate, RSA key pair loading), issued certificates get their own key pair now, moved the login users to the configuration, updated NuGet packages, moved to Net 10.0, rewrote the readme and the how to use file.
* **Version 1.0.0.0 (2024-09-30)** : 1.0 release.