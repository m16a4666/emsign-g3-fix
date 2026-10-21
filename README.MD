# emsign-g3-fix

One-shot fix for the emSign trust store over-blocking.

The original remediation blacklisted **all four** emSign roots. Only
`emSign ECC Root CA - G3` is affected by
[Mozilla Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449);
C3 / C1 / G1 are unrelated and should keep their trust.

This script:
- keeps `emSign ECC Root CA - G3` blacklisted (`!` prefix)
- restores trust for `emSign ECC Root CA - C3`, `emSign Root CA - C1`, `emSign Root CA - G1`
- backs up `/etc/ca-certificates.conf` and the PEM bundle first
- re-runs `update-ca-certificates --fresh`
- self-verifies and exits non-zero if the result is wrong

## One-liner

```bash
curl -fsSL https://raw.githubusercontent.com/<you>/emsign-g3-fix/main/fix-emsign-g3only.sh | sudo bash
```

Or safer (download, inspect, then run):

```bash
curl -fsSL -o /tmp/fix-emsign-g3.sh \
  https://raw.githubusercontent.com/<you>/emsign-g3-fix/main/fix-emsign-g3only.sh
less /tmp/fix-emsign-g3.sh
sudo bash /tmp/fix-emsign-g3.sh
```

## Verify

```bash
grep -i emsign /etc/ca-certificates.conf
grep -c "emSign ECC Root CA - G3" /etc/ssl/certs/ca-certificates.crt   # 0
```

## Supported

Debian / Ubuntu (uses `ca-certificates.conf` + `update-ca-certificates`).

## License

MIT