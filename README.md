# certforge

ACME certificate manager with DANE and systemd integration.

Certforge automates TLS certificate issuance and renewal using the ACME protocol (RFC 8555). It supports DNS-01 challenges via RFC 2136, HTTP-01 and TLS-ALPN-01 challenges for IP address certificates, publishes DANE TLSA records, and integrates tightly with systemd for secret storage, service management, and scheduled operation.

## Features

- **Multiple challenge types** -- DNS-01 (RFC 2136 with TSIG), HTTP-01 (standalone server or webroot), TLS-ALPN-01 (standalone TLS server). Per-domain solver assignment.
- **IP address certificates** -- issue certificates for IPv4 and IPv6 addresses using HTTP-01 or TLS-ALPN-01.
- **DANE TLSA** -- automatically publishes TLSA records (RFC 6698/7671/7672) after certificate issuance. Supports DANE-EE with SPKI selector for zero-downtime renewals.
- **Key rotation with pre-publication** -- when rotating keys, new TLSA records are published alongside the old ones and certforge waits for the old TTL to expire before completing the renewal.
- **Multiple servers, one certificate** -- a single certificate's DANE block can list multiple TLSA names (e.g., `_25._tcp.mx1.example.com`, `_25._tcp.mx2.example.com`) for services sharing a key.
- **systemd credentials** -- private keys and TSIG secrets can be stored as encrypted systemd credentials (`systemd-creds`). Services access the same files via `LoadCredentialEncrypted=`.
- **systemd hooks** -- reload or restart systemd units after renewal via D-Bus. Also supports arbitrary command hooks.
- **Timer-driven** -- ships with a systemd service and timer for daily renewal checks with randomized delay.
- **TOML configuration** -- declarative config with named DNS clients, named solvers, and per-certificate DANE and hook blocks.

## Installation

### From source

```
cargo install --path .
```

### Arch Linux

```
makepkg -si
```

### Debian/Ubuntu

Download the `.deb` from the [releases page](https://github.com/rkivalin/certforge/releases) or build from source:

```
dpkg-buildpackage -us -uc
```

## Quick start

1. Edit `/etc/certforge/config.toml` (see [examples/config.toml](examples/config.toml) for reference):

```toml
[acme]
account_key_path = "/etc/certforge/account.key"
contact = ["mailto:admin@example.com"]

[dns.main]
server = "ns1.example.com"
zone = "example.com"
tsig_key_path = "/etc/certforge/tsig.key"
tsig_key_name = "certforge."

[solver.dns]
type = "dns-01"
dns = "main"

[[certificate]]
name = "mail"
domains = ["mail.example.com"]
solver = "dns"
key_path = "/etc/certforge/keys/mail.key"
cert_path = "/etc/certforge/certs/mail.pem"

  [[certificate.dane]]
  dns = "main"
  names = ["_25._tcp.mail.example.com"]

  [[certificate.hook]]
  type = "systemd-reload"
  unit = "postfix.service"
```

2. Validate:

```
certforge config-check
```

3. Issue certificates:

```
certforge renew
```

4. Enable the timer for automatic renewal:

```
systemctl enable --now certforge.timer
```

## Usage

```
certforge [OPTIONS] <COMMAND>

Commands:
  renew         Check all certificates and renew those expiring soon
  status        Show status of all configured certificates
  issue         Force-issue a specific certificate
  dane-publish  Force-(re)publish DANE TLSA records
  dane-check    Query and verify published TLSA records against current certs
  config-check  Validate configuration file
  init          Print systemd-creds encrypt commands for initial setup
  account       Manage ACME account

Options:
  -c, --config <PATH>        Config file [default: /etc/certforge/config.toml]
  -v, --verbose...           Increase verbosity (-v, -vv, -vvv)
  -n, --dry-run              Show what would be done without making changes
      --state-dir <PATH>     State directory [default: /var/lib/certforge]
```

## Configuration

### DNS clients

Named DNS client connections are defined in `[dns.*]` blocks and referenced by solvers and DANE blocks:

```toml
[dns.main]
server = "ns1.example.com"
zone = "example.com"
tsig_key_path = "/etc/certforge/tsig.key"
tsig_key_name = "certforge."
tsig_algorithm = "hmac-sha256"   # hmac-sha256, hmac-sha384, or hmac-sha512
```

### Challenge solvers

Solvers are defined in `[solver.*]` blocks. Each certificate references a solver by name.

**DNS-01** -- publishes TXT records via RFC 2136 dynamic DNS updates:
```toml
[solver.dns]
type = "dns-01"
dns = "main"          # references a [dns.*] block
```

**HTTP-01** -- serves challenge tokens over HTTP:
```toml
# Standalone mode: certforge runs a temporary HTTP server
[solver.http]
type = "http-01"
listen = "[::]:80"

# Webroot mode: writes tokens for an existing web server
[solver.webroot]
type = "http-01"
webroot = "/var/www/acme"
```

**TLS-ALPN-01** -- serves challenge certificates via TLS with ALPN `acme-tls/1`:
```toml
[solver.tls]
type = "tls-alpn-01"
listen = "[::]:443"
```

### Certificates

Certificates reference solvers by name. Use `solver` for a single solver or `solvers` for per-domain assignment:

```toml
# All domains use the same solver
[[certificate]]
name = "web"
domains = ["example.com", "www.example.com"]
solver = "dns"

# IP address certificate (requires shortlived profile, ~6 day validity)
[[certificate]]
name = "dns-server"
domains = ["dns.example.com", "203.0.113.1", "2001:db8::1"]
solvers = ["dns", "http", "http"]
profile = "shortlived"
renew_before_days = 3
```

If neither `solver` nor `solvers` is set, the global `default_solver` is used.

### ACME profiles

Some ACME providers require a specific profile for certain certificate types. Set `profile` on a certificate to select one. For example, Let's Encrypt requires the `shortlived` profile for IP address certificates (see [Let's Encrypt profiles](https://letsencrypt.org/docs/profiles/)).

### Credential storage

Every secret (ACME account key, TSIG keys, TLS private keys) supports two modes:

- **`*_credential`** -- full path to a `systemd-creds` encrypted file. Certforge decrypts at runtime via `systemd-creds decrypt`. Services access the same file via `LoadCredentialEncrypted=` in their unit files.
- **`*_path`** -- plain file on disk. Simpler setup, suitable for development or environments without TPM2.

Run `certforge init` to generate the `systemd-creds encrypt` commands for your configuration.

### DANE

Each certificate can have multiple `[[certificate.dane]]` blocks. A DANE block references a `[dns.*]` client for TLSA record publication:

| Field | Default | Description |
|-------|---------|-------------|
| `dns` | required | Name of a `[dns.*]` client for RFC 2136 updates |
| `usage` | `ee` | TLSA usage: `ee` (3), `ta` (2), `pkix-ee` (1), `pkix-ta` (0) |
| `selector` | `spki` | `spki` (1) or `full` (0) |
| `matching` | `sha256` | `sha256` (1), `sha512` (2), or `full` (0) |
| `names` | required | List of TLSA DNS names (e.g., `_25._tcp.mail.example.com`) |
| `ttl` | `300` | TTL for TLSA records |
| `pre_publish` | `false` | Pre-publish new TLSA before key rotation |

With `usage = "ee"` and `selector = "spki"` (the recommended DANE-EE configuration), the TLSA record depends only on the public key. This means the record survives certificate renewal as long as the key is not rotated.

### Post-renewal hooks

```toml
[[certificate.hook]]
type = "systemd-reload"    # or "systemd-restart"
unit = "postfix.service"

[[certificate.hook]]
type = "command"
command = ["/usr/local/bin/deploy-cert.sh", "--name", "mail"]
```

Hooks run sequentially after a successful renewal. A hook failure is logged but does not prevent subsequent hooks from running.

## systemd integration

The package ships with:

- `certforge.service` -- oneshot service that runs `certforge renew`
- `certforge.timer` -- daily timer with randomized delay

```
systemctl enable --now certforge.timer
```

For encrypted credentials, add `LoadCredentialEncrypted=` directives to service units that need access to TLS keys. Run `certforge init` to see the required directives.

## Known limitations

- **TSIG HMAC-SHA-512**: BIND 9.18+ truncates HMAC-SHA-512 MACs by default, and the underlying DNS library (hickory-dns) does not support verifying truncated HMACs. Use `hmac-sha256` instead.
- RSA key types not yet supported (ECDSA only).
- `dane-check` shows expected TLSA records but does not query DNS to verify.

## License

MIT
