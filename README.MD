# emsign-g3-fix

Idempotent remediation for the emSign trust store.

The original remediation for
[Mozilla Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
blacklisted **all four** emSign roots. Only
`emSign ECC Root CA - G3` is affected by the compromised intermediate CAs;
C3 / C1 / G1 are unrelated and should keep their trust.

This script normalizes the trust store to:

| Root | State |
|---|---|
| emSign ECC Root CA - G3 | **blocked** (`!` prefix) |
| emSign ECC Root CA - C3 | trusted |
| emSign Root CA - C1     | trusted |
| emSign Root CA - G1     | trusted |

It is safe to run on any of these starting states and re-running is a no-op:

- **clean**: no emSign remediation applied yet
- **polluted**: all four roots were blocked by the previous script
- **already fixed**: G3 blocked, others trusted

## One-liner

```bash
curl -fsSL https://raw.githubusercontent.com/<you>/emsign-g3-fix/main/fix-emsign-g3only.sh | sudo bash
```

Recommended: download, inspect, then run.

```bash
curl -fsSL -o /tmp/fix-emsign-g3.sh \
  https://raw.githubusercontent.com/<you>/emsign-g3-fix/main/fix-emsign-g3only.sh
less /tmp/fix-emsign-g3.sh
sudo bash /tmp/fix-emsign-g3.sh
```

Pin to a release tag for production:

```bash
curl -fsSL -o /tmp/fix-emsign-g3.sh \
  https://raw.githubusercontent.com/<you>/emsign-g3-fix/v1.0.0/fix-emsign-g3only.sh
sudo bash /tmp/fix-emsign-g3.sh
```

## Verify

```bash
# only the G3 line should start with !
grep -i emsign /etc/ca-certificates.conf

# C3 / C1 / G1 symlinks present, G3 symlink absent
ls /etc/ssl/certs/emSign*.pem
```

Expected:

```
mozilla/emSign_ECC_Root_CA_-_C3.crt
!mozilla/emSign_ECC_Root_CA_-_G3.crt
mozilla/emSign_Root_CA_-_C1.crt
mozilla/emSign_Root_CA_-_G1.crt
```

```
/etc/ssl/certs/emSign_ECC_Root_CA_-_C3.pem
/etc/ssl/certs/emSign_Root_CA_-_C1.pem
/etc/ssl/certs/emSign_Root_CA_-_G1.pem
```

## Backups and rollback

Every modified file is copied to `/var/backups/emsign-g3only-<timestamp>/`
before being touched. The script prints the rollback command on success:

```bash
cp -a /var/backups/emsign-g3only-<timestamp>/* /etc/
update-ca-certificates --fresh
```

## Requirements

- Debian / Ubuntu or derivative (`ca-certificates.conf` + `update-ca-certificates`)
- `python3`
- root

## Notes

- Browsers (Chrome / Edge / Firefox) do not use the system CA store and are
  unaffected by this script. They handle the compromise via CRLSet / OneCRL.
- This script targets the blind spots: `curl`, `Python requests`, `Git`,
  `Docker`, and any other tool that reads the system root store without doing
  online CRL/OCSP checks.
- RHEL / Fedora use p11-kit (`update-ca-trust`). This script does not modify
  those stores. Contributions welcome.

## License

MIT
