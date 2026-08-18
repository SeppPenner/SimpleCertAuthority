SimpleCertAuthority
====================================

SimpleCertAuthority is a small self hosted certification authority. It keeps a root CA and a sub CA
on disk and issues, verifies, renews and revokes certificates over a REST API. It runs as a Windows
service or under systemd.

[![GitHub issues](https://img.shields.io/github/issues/SeppPenner/SimpleCertAuthority.svg)](https://github.com/SeppPenner/SimpleCertAuthority/issues)
[![GitHub forks](https://img.shields.io/github/forks/SeppPenner/SimpleCertAuthority.svg)](https://github.com/SeppPenner/SimpleCertAuthority/network)
[![GitHub stars](https://img.shields.io/github/stars/SeppPenner/SimpleCertAuthority.svg)](https://github.com/SeppPenner/SimpleCertAuthority/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://raw.githubusercontent.com/SeppPenner/SimpleCertAuthority/master/License.txt)
[![Blogger](https://img.shields.io/badge/Follow_me_on-blogger-orange)](https://franzhuber23.blogspot.de/)
[![Patreon](https://img.shields.io/badge/Patreon-F96854?logo=patreon&logoColor=white)](https://patreon.com/SeppPennerOpenSourceDevelopment)
[![PayPal](https://img.shields.io/badge/PayPal-00457C?logo=paypal&logoColor=white)](https://paypal.me/th070795)

## What it does

On the first start the service creates its own certificate hierarchy:

1. An RSA key pair for the root certification authority, stored under `Keys`.
2. A self signed root certificate valid for five years, stored under `RootCertificates`.
3. A sub CA certificate valid for three years, signed by the root certificate and stored under
   `SubCaCertificates`.

Certificates are issued by the sub CA. Every issued certificate and every sub CA certificate gets
its own key pair, so the key of a certification authority is never handed out. The API delivers an
issued certificate as a PKCS#12 file including its private key.

Revocation is kept simple: the serial number of a revoked certificate is appended to a JSON list
under `RevokedCertificates` and served over the API. There is no certificate revocation list and no
OCSP responder.

## The API

An OpenAPI document and a Swagger UI are served at `/swagger`.

| Method | Route | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `api/Login/login` | anonymous | Returns a JSON web token for a configured user, valid for 120 minutes. |
| GET | `api/Certificate/getRootCertificates` | anonymous | All root certificates as a ZIP of `.cer` files. |
| GET | `api/Certificate/getSubCaCertificates` | anonymous | All sub CA certificates as a ZIP of `.cer` files. |
| GET | `api/Certificate/getRevokedCertificateSerialNumbers` | anonymous | The revoked serial numbers as JSON. |
| POST | `api/Certificate/createRootCertificate` | token | Creates another root certificate. |
| POST | `api/Certificate/createSubCaCertificate` | token | Creates another sub CA certificate. |
| POST | `api/Certificate/generateCertificate` | token | Issues a certificate, returns a PKCS#12 file. |
| POST | `api/Certificate/renewCertificate` | token | Issues a successor certificate, returns a PKCS#12 file. |
| POST | `api/Certificate/verifyCertificate` | token | `200` when the certificate is valid, `409` with the reason when it is not. |
| POST | `api/Certificate/revokeCertificate` | token | Stores the serial number of the certificate as revoked. |

Everything that issues, changes or inspects a certificate needs a token. Open without one are the
login itself and the three downloads a client needs before it can log in: the root certificates, the
sub CA certificates and the revoked serial numbers. Those three are public trust material anyway,
every certificate carries the chain and a revocation list is meant to be readable.

## Basic usage

Check out the how to use file [here](https://github.com/SeppPenner/SimpleCertAuthority/blob/master/HowToUse.md).

Change history
--------------

See the [Changelog](https://github.com/SeppPenner/SimpleCertAuthority/blob/master/Changelog.md).
