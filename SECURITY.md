# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.13  | :white_check_mark: |
| < 0.1.13 | :x:               |

## Known Issue in 0.1.10 and Earlier

Versions up to and including 0.1.10 did **not** encrypt private keys when a
passphrase was supplied. The key header claimed `aes256-ctr` and `bcrypt`, but
the private key was stored in the clear and the passphrase was written into the
key's comment field. Such files also could not be loaded by OpenSSH.

If you generated a key with a passphrase using an affected version, treat both
the key and the passphrase as compromised: generate a new mnemonic and key with
0.1.13 or later, replace the public key wherever it was authorised, and stop
using that passphrase elsewhere. Keys generated without a passphrase are
unaffected.

## Reporting a Vulnerability

We take the security of mnemossh seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please use GitHub's security features:

1. Navigate to the **[Security tab](https://github.com/abkvme/mnemossh/security)** of this repository
2. Use the available security reporting options (Security Advisories or vulnerability reporting)

If you cannot find an appropriate reporting mechanism, please create a new security advisory directly.

### What to Include

- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested fixes (optional)

Thank you for helping keep mnemossh secure!
