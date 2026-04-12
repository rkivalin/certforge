# Changelog

## 0.4.0 (unreleased)

### Features

### Fixes

### Changes

## 0.3.0 (2026-04-12)

### Fixes

- Add DNS propagation delay before ACME challenge validation

## 0.2.0 (2026-04-12)

### Fixes

- Build on Ubuntu 22.04 for glibc 2.35 compatibility (Debian 12+)

## 0.1.0 (2026-04-12)

Initial release.

### Features

- ACME certificate issuance and renewal via DNS-01 challenges (RFC 8555)
- RFC 2136 dynamic DNS updates with TSIG authentication (HMAC-SHA256, HMAC-SHA512)
- DANE TLSA record publication (RFC 6698/7671/7672)
  - DANE-EE, DANE-TA, PKIX-EE, PKIX-TA usage types
  - SPKI and full certificate selectors
  - SHA-256, SHA-512, and exact matching
  - Multiple TLSA names per certificate for multi-server deployments
- Key rotation with DANE pre-publication protocol to avoid TLSA breakage
- ECDSA P-256 and P-384 key generation
- systemd credential integration (`systemd-creds encrypt`/`decrypt`) for private keys and TSIG secrets
- systemd unit reload/restart hooks via D-Bus
- Arbitrary command hooks after renewal
- TOML configuration with per-zone DNS server overrides
- CLI commands: `renew`, `status`, `issue`, `dane-publish`, `dane-check`, `config-check`, `init`, `account`
- Dry-run mode (`--dry-run`)
- Automatic cleanup of ACME challenge TXT records on failure
- DNS update response code checking (REFUSED, NOTAUTH, NXRRSET, etc.)
- Automatic base64 decoding of TSIG keys
- DNS server hostname resolution (not limited to IP addresses)
- Example systemd service and timer units
- Arch Linux PKGBUILD and Debian packaging

### Known limitations

- RSA key types not yet supported (ECDSA only)
- `dane-check` shows expected TLSA records but does not query DNS to verify
- ACME account deactivation not yet implemented
- DNS updates use TCP only (UDP not yet supported)
