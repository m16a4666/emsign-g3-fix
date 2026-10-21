#!/usr/bin/env bash
#
# fix-emsign-g3only.sh
#
# Keep emSign ECC Root CA - G3 blocked (Mozilla Bug 2083449),
# restore trust for C3 / C1 / G1 which are unrelated to the incident.
#
# Supported: Debian / Ubuntu (ca-certificates.conf + update-ca-certificates)
# License: MIT
#
set -e

[[ "$(id -u)" -eq 0 ]] || { echo "[x] run as root (sudo)"; exit 3; }

CONF=/etc/ca-certificates.conf
BUNDLE=/etc/ssl/certs/ca-certificates.crt
TS=$(date +%Y%m%d-%H%M%S)
BK=/var/backups/emsign-g3only-$TS
PY=$(command -v python3 || command -v python || true)

echo "=== emSign: keep G3 blocked, restore C3/C1/G1 ==="

# ---------------------------------------------------------------
# 0. 源证书是否还在（否则 --fresh 也生成不回来）
# ---------------------------------------------------------------
missing=0
for f in \
  /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt \
  /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_C3.crt \
  /usr/share/ca-certificates/mozilla/emSign_Root_CA_-_C1.crt \
  /usr/share/ca-certificates/mozilla/emSign_Root_CA_-_G1.crt ; do
  [[ -f "$f" ]] || { echo "[x] missing: $f"; missing=1; }
done
if [[ $missing -eq 1 ]]; then
  echo "[!] reinstall ca-certificates first:"
  echo "    apt-get install --reinstall ca-certificates"
  exit 2
fi

# ---------------------------------------------------------------
# 1. 备份
# ---------------------------------------------------------------
mkdir -p "$BK"
cp -a "$CONF" "$BK/" 2>/dev/null || true
[[ -f "$BUNDLE" ]] && cp -a "$BUNDLE" "$BK/" || true
echo "[+] backup: $BK"

# ---------------------------------------------------------------
# 2. 改 ca-certificates.conf
#    - G3: 确保带 ! 前缀
#    - C3 / C1 / G1: 去掉 ! 前缀
# ---------------------------------------------------------------
if [[ -n "$PY" ]]; then
  "$PY" - "$CONF" <<'PY'
import sys
p = sys.argv[1]
with open(p, encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()
out, g3, rest = [], 0, 0
for line in lines:
    s = line.lstrip()
    if s.startswith('#'):
        out.append(line); continue
    indent = line[:len(line)-len(s)]
    bang = s.startswith('!')
    body = s[1:] if bang else s
    low = body.lower()
    if 'emsign' not in low:
        out.append(line); continue
    if 'g3' in low:
        out.append(indent + ('!' + body if not bang else body))
        g3 += 1
    else:
        out.append(indent + body)
        rest += 1
with open(p, 'w', encoding='utf-8') as f:
    f.writelines(out)
print(f"    g3 blocked={g3}, restored={rest}")
PY
else
  # 无 python 时的 sed 兜底（只处理 mozilla/ 命名）
  sed -i -E 's|^([[:space:]]*)mozilla/emSign_ECC_Root_CA_-_G3|!mozilla/emSign_ECC_Root_CA_-_G3|' "$CONF"
  sed -i -E 's|^!([[:space:]]*mozilla/emSign_(ECC_)?Root_CA_-_(C3|C1|G1))|\1|' "$CONF"
  echo "    (sed fallback applied)"
fi

# ---------------------------------------------------------------
# 3. 重新生成 bundle
# ---------------------------------------------------------------
if command -v update-ca-certificates >/dev/null 2>&1; then
  update-ca-certificates --fresh >/dev/null 2>&1 \
    || update-ca-certificates >/dev/null 2>&1 || true
  echo "[+] regenerated ca-certificates bundle"
fi

# ---------------------------------------------------------------
# 4. 自校验
# ---------------------------------------------------------------
echo
echo "--- $CONF ---"
grep -i emsign "$CONF" || echo "  (no emSign lines)"
echo
echo "--- $BUNDLE ---"
rc=0
for n in \
  "emSign ECC Root CA - C3" \
  "emSign Root CA - C1" \
  "emSign Root CA - G1" \
  "emSign ECC Root CA - G3" ; do
  c=$(grep -c -- "$n" "$BUNDLE" 2>/dev/null || true); c=${c:-0}
  printf "  %-30s : %s\n" "$n" "$c"
  if [[ "$n" == *G3 && "$c" != "0" ]]; then rc=2; fi
  if [[ "$n" != *G3 && "$c" == "0" ]]; then rc=2; fi
done

echo
if [[ $rc -eq 0 ]]; then
  echo "[+] done. G3 blocked; C3 / C1 / G1 restored."
  echo "[+] rollback: cp -a $BK/* /etc/ && update-ca-certificates --fresh"
else
  echo "[x] verification mismatch, backup at $BK"
  exit 2
fi