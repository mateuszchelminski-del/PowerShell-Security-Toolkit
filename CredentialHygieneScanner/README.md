# Credential Hygiene Scanner

## Description
Performs read-only checks to identify potential credential exposure risks without accessing or extracting secrets.

## Collects
- Credential Manager target names
- Plaintext credential pattern indicators (regex-based)
- Browser password store presence (file existence only)
- VPN configuration file presence

## Usage
```powershell
.\Invoke-CredentialHygieneScan.ps1
