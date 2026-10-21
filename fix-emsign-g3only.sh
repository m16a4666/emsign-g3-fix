#!/usr/bin/env bash
#
# fix-emsign-g3only.sh
#
# Idempotent remediation for the emSign trust store:
#   - emSign ECC Root CA - G3  -> BLOCKED  (Mozilla Bug 2083449)
#   - emSign ECC Root CA - C3  -> trusted
#   - emSign Root CA - C1      -> trusted
#   - emSign Root CA - G1      -> trusted
#
# Safe on clean / polluted / already-fixed systems. Re-running is a no-op.
#
# Targets: Debian / Ubuntu (and derivatives) using ca-certificates.conf
#          + update-ca-certificates.
#
# License: MIT
#
set -euo pipefail

CONF=/etc/ca-certificates.conf
SRC=/usr/share/ca-certificates/mozilla
CERTS=/etc/ssl/certs
BUNDLE=$CERTS/ca-certificates.crt
TS=$(date +%Y%m%d-%H%M%S)
BK=/var/backups/emsign-g3only-$TS

log()  { printf '[%s] %s\n' "$1" "$2"; }
info() { log ' *' "$*"; }
ok()   { log ' +' "$*"; }
warn() { log ' !' "$*"; }
err()  { log ' x' "$*" >&2; }

# ---- preflight -------------------------------------------------------------
[[ "$(id -u)" -eq 0 ]] || { err "must be run as root (try: sudo bash $0)"; exit 3; }
[[ -f "$CONF" ]] || { err "$CONF not found; this script targets Debian/Ubuntu"; exit 3; }

PY=$(command -v python3 || command -v python || true)
[[ -n "$PY" ]] || { err "python3 required"; exit 3; }

for f in emSign_ECC_Root_CA_-_C3.crt \
         emSign_Root_CA_-_C1.crt \
         emSign_Root_CA_-_G1.crt; do
    if [[ ! -f "$SRC/$f" ]]; then
        err "source missing: $SRC/$f"
        err "reinstall first: apt-get install --reinstall ca-certificates"
        exit 2
    fi
done

# ---- backup ----------------------------------------------------------------
mkdir -p "$BK"
cp -a "$CONF" "$BK/" 2>/dev/null || true
[[ -f "$BUNDLE" ]] && cp -a "$BUNDLE" "$BK/" 2>/dev/null || true
info "backup: $BK"

# ---- normalize conf --------------------------------------------------------
# G3 must be prefixed with '!'; C3/C1/G1 must not. Missing entries are added.
"$PY" - "$CONF" <<'PY'
import os, sys
p = sys.argv[1]
targets = {
    'emSign_ECC_Root_CA_-_G3.crt': True,    # True = block
    'emSign_ECC_Root_CA_-_C3.crt': False,
    'emSign_Root_CA_-_C1.crt':     False,
    'emSign_Root_CA_-_G1.crt':     False,
}
low2orig = {k.lower(): (k, v) for k, v in targets.items()}

with open(p, encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

out, seen = [], set()
for line in lines:
    s = line.lstrip()
    if not s.strip() or s.startswith('#'):
        out.append(line); continue
    indent = line[:len(line)-len(s)]
    bang = s.startswith('!')
    body = (s[1:] if bang else s).rstrip('\n')
    base = os.path.basename(body).lower()
    if base not in low2orig:
        out.append(line); continue
    seen.add(base)
    blocked = low2orig[base][1]
    out.append(indent + ('!' if blocked else '') + body + '\n')

for base, (orig, blocked) in low2orig.items():
    if base in seen:
        continue
    out.append(('!' if blocked else '') + 'mozilla/' + orig + '\n')

with open(p, 'w', encoding='utf-8') as f:
    f.writelines(out)
print(f"    normalized {len(seen)} existing, added {len(targets)-len(seen)} missing")
PY
ok "updated $CONF"

# ---- regenerate bundle (errors are NOT swallowed) --------------------------
info "running update-ca-certificates --fresh"
if ! update-ca-certificates --fresh; then
    err "update-ca-certificates --fresh failed; backup at $BK"
    exit 2
fi
ok "regenerated CA bundle"

# ---- verify via symlinks (ground truth) ------------------------------------
rc=0
for pair in "C3:emSign_ECC_Root_CA_-_C3.pem" \
            "C1:emSign_Root_CA_-_C1.pem" \
            "G1:emSign_Root_CA_-_G1.pem"; do
    name="${pair%%:*}"; file="${pair##*:}"
    if [[ -e "$CERTS/$file" ]]; then
        ok "$name trusted ($CERTS/$file)"
    else
        err "$name MISSING: $CERTS/$file"
        rc=2
    fi
done

if [[ -e "$CERTS/emSign_ECC_Root_CA_-_G3.pem" ]]; then
    err "G3 still trusted: $CERTS/emSign_ECC_Root_CA_-_G3.pem"
    rc=2
else
    ok "G3 blocked"
fi

echo
if [[ $rc -eq 0 ]]; then
    ok "SUCCESS: G3 blocked; C3 / C1 / G1 trusted"
    info "rollback: cp -a $BK/* /etc/ && update-ca-certificates --fresh"
else
    err "verification failed; backup at $BK"
fi
exit $rc
