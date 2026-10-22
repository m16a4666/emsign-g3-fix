#!/usr/bin/env bash
# Debian/Ubuntu emSign trust remediation. MIT license.
# Historical filename retained for download links; policy is now NSS 3.131.1.
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'ERROR: Python 3.8+ is required.' >&2
    exit 3
fi
python3 - "$@" <<'PYTHON'
import argparse
import base64
import contextlib
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

VERSION = '2.0.0'
# Certificate SHA-256: Mozilla/certifi roots; SPKI SHA-256: Mozilla incident notice.
CERT_HASHES = {
    '125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f': 'C1',
    'bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3': 'C3',
    '40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367': 'G1',
}
SPKI_HASHES = {
    '8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782': 'G3',
    'c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9': 'TLS-G3',
    'bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3': 'AAA',
}
FILENAMES = {
    'emsign_ecc_root_ca_-_g3.crt': 'G3',
    'emsign_ecc_root_ca_-_c3.crt': 'C3',
    'emsign_root_ca_-_c1.crt': 'C1',
    'emsign_root_ca_-_g1.crt': 'G1',
    'emsign_root_tls_ca_-_g3.crt': 'TLS-G3',
    'comodo_aaa_services_root.crt': 'AAA',
}
PEM = re.compile(rb'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----', re.S)


class FixError(Exception):
    pass


def tlv(data, offset):
    """Read one definite-length DER field: tag, content offset, end."""
    start = offset
    if offset + 2 > len(data):
        raise FixError('truncated DER certificate')
    tag, length = data[offset:offset + 2]
    offset += 2
    if length & 128:
        count = length & 127
        if not 1 <= count <= 4 or offset + count > len(data):
            raise FixError('invalid DER length')
        length = int.from_bytes(data[offset:offset + count], 'big')
        offset += count
    end = offset + length
    if end > len(data) or end <= start:
        raise FixError('invalid DER field')
    return tag, offset, end


def identity(der):
    tag, outer, end = tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise FixError('invalid X.509 certificate sequence')
    tag, offset, tbs_end = tlv(der, outer)
    if tag != 0x30:
        raise FixError('invalid TBSCertificate')
    if der[offset] == 0xa0:
        _, _, offset = tlv(der, offset)
    for _ in range(5):  # serial, signature, issuer, validity, subject
        _, _, offset = tlv(der, offset)
    tag, _, spki_end = tlv(der, offset)
    if tag != 0x30 or spki_end > tbs_end:
        raise FixError('invalid SubjectPublicKeyInfo')
    key_hash = hashlib.sha256(der[offset:spki_end]).hexdigest()
    cert_hash = hashlib.sha256(der).hexdigest()
    return SPKI_HASHES.get(key_hash) or CERT_HASHES.get(cert_hash)


def identities(data):
    blocks = PEM.findall(data)
    if data.count(b'-----BEGIN CERTIFICATE-----') != len(blocks):
        raise FixError('incomplete PEM certificate')
    found = set()
    for block in blocks:
        try:
            der = base64.b64decode(re.sub(rb'\s+', b'', block), validate=True)
            found.add(identity(der))
        except (ValueError, IndexError) as exc:
            raise FixError('invalid PEM certificate: ' + str(exc)) from exc
    return found - {None}


def read_ids(path, required=False):
    if not path.exists() and not path.is_symlink():
        if required:
            raise FixError('missing CA bundle: ' + str(path))
        return set()
    data = path.read_bytes()
    if required and not PEM.search(data):
        raise FixError('empty or invalid CA bundle: ' + str(path))
    return identities(data)


def normalized(data, source, blocked):
    """Only disable existing entries; preserve unrelated bytes and G1 policy."""
    output, changes = [], []
    for line in data.decode('latin1').splitlines(keepends=True):
        body = line.strip()
        if not body or body.startswith('#'):
            output.append(line)
            continue
        body = body.lstrip('!').strip()
        rel = PurePosixPath(body)
        if rel.is_absolute() or '..' in rel.parts:
            raise FixError('unsafe certificate path in configuration: ' + body)
        targets = {FILENAMES.get(rel.name.lower())}
        targets.update(read_ids(source / body))
        if targets & blocked:
            replacement = '!' + body + ('\r\n' if line.endswith('\r\n') else '\n')
            output.append(replacement)
            if replacement != line:
                changes.append(body)
        else:
            output.append(line)
    return ''.join(output).encode('latin1'), changes


def audit(bundle, certs, local):
    bundle_ids = read_ids(bundle, required=True)
    directory_ids = set()
    # Actual certificate bytes, including renamed files and hash symlinks.
    for path in certs.iterdir():
        if path.is_file() and path != bundle:
            directory_ids.update(read_ids(path))
    local_ids = set()
    for path in local.rglob('*.crt'):
        local_ids.update(read_ids(path))
    return bundle_ids | directory_ids, local_ids


def atomic_write(path, data, metadata):
    fd, name = tempfile.mkstemp(prefix='.emsign-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        shutil.copystat(metadata, name)
        if hasattr(os, 'chown'):
            owner = metadata.stat()
            os.chown(name, owner.st_uid, owner.st_gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def rebuild(command):
    print('[*] Regenerating system trust store', flush=True)
    subprocess.run([command, '--fresh'], check=True)


def backup(conf, bundle, backup_root):
    backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = Path(tempfile.mkdtemp(prefix='emsign-', dir=str(backup_root)))
    for src, rel in ((conf, 'etc/ca-certificates.conf'),
                     (bundle, 'etc/ssl/certs/ca-certificates.crt')):
        dest = directory / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        if hasattr(os, 'chown'):
            owner = src.stat()
            os.chown(dest, owner.st_uid, owner.st_gid)
    print('[*] Backup: ' + str(directory), flush=True)
    print('[*] Rollback: sudo bash fix-emsign-g3only.sh --rollback ' + shlex.quote(str(directory)), flush=True)
    return directory


@contextlib.contextmanager
def lock(path):
    import fcntl
    fd = os.open(str(path), os.O_RDONLY)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise FixError('another remediation process is running') from exc
        yield
    finally:
        os.close(fd)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Debian/Ubuntu emSign trust remediation (NSS 3.131.1).')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--check', '--verify', action='store_true', help='read-only audit; exit 1 if changes needed')
    modes.add_argument('--dry-run', action='store_true', help='preview without writes; exit 1 if changes needed')
    modes.add_argument('--rollback', metavar='BACKUP', help='restore configuration and regenerate trust store')
    parser.add_argument('--strict', action='store_true', help='also disable G1, TLS-G3 and AAA (compatibility impact)')
    parser.add_argument('--backup-dir', type=Path, default=Path('/var/backups/emsign-trust-fix'))
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args(argv)
    if args.rollback and args.strict:
        parser.error('--strict cannot be combined with --rollback')
    return args


def execute(args, root=Path('/'), updater=None):
    # root/updater are injected by offline tests only; never accepted from CLI/env.
    conf = root / 'etc/ca-certificates.conf'
    source = root / 'usr/share/ca-certificates'
    certs = root / 'etc/ssl/certs'
    bundle = certs / 'ca-certificates.crt'
    local = root / 'usr/local/share/ca-certificates'
    blocked = {'G3', 'C1', 'C3'}
    if args.strict:
        blocked.update({'G1', 'TLS-G3', 'AAA'})
    readonly = args.check or args.dry_run
    if not readonly and os.geteuid() != 0:
        raise FixError('run apply/rollback as root (sudo bash fix-emsign-g3only.sh)')
    if conf.is_symlink() or not conf.is_file() or not certs.is_dir():
        raise FixError('requires Debian/Ubuntu ca-certificates.conf and /etc/ssl/certs; configuration must be a regular file')
    command = updater or shutil.which('update-ca-certificates')
    if not readonly and not command:
        raise FixError('update-ca-certificates is required')
    with contextlib.nullcontext() if readonly else lock(root / 'etc'):
        original = conf.read_bytes()
        if args.rollback:
            saved = Path(args.rollback).resolve() / 'etc/ca-certificates.conf'
            if not saved.is_file() or saved.is_symlink():
                raise FixError('backup configuration missing or not a regular file: ' + str(saved))
            bk = backup(conf, bundle, args.backup_dir)
            atomic_write(conf, saved.read_bytes(), conf)
            try:
                rebuild(command)
                read_ids(bundle, required=True)
            except (OSError, subprocess.CalledProcessError, FixError):
                atomic_write(conf, original, bk / 'etc/ca-certificates.conf')
                rebuild(command)
                raise
            print('[+] Configuration restored; system bundle regenerated. Previous trust may be re-enabled.')
            return 0
        desired, changes = normalized(original, source, blocked)
        active, local_ids = audit(bundle, certs, local)
        residual = active & blocked
        for name in sorted(blocked):
            print('[*] {}: {}'.format(name, 'present in generated trust store' if name in active else 'absent from generated trust store'))
        for name in sorted(((active | local_ids) & {'AAA', 'TLS-G3'}) - blocked):
            print('[!] {} remains: known cross-signing path; consider --strict or distributor updates.'.format(name))
        print('[*] Configuration entries to disable: ' + str(len(changes)))
        for entry in changes:
            print('    !' + entry)
        if local_ids & blocked:
            raise FixError('target CA in /usr/local/share/ca-certificates: ' + ', '.join(sorted(local_ids & blocked)) + '; remove the local trust override and rerun')
        if readonly:
            return int(bool(changes or residual))
        if not changes and not residual:
            print('[+] Selected policy already satisfied; no files changed.')
            return 0
        bk = backup(conf, bundle, args.backup_dir)
        try:
            if changes:
                atomic_write(conf, desired, conf)
            rebuild(command)
            active, _ = audit(bundle, certs, local)
            remaining_conf, _ = normalized(conf.read_bytes(), source, blocked)
            if active & blocked or remaining_conf != conf.read_bytes():
                raise FixError('post-update verification failed; selected roots remain trusted or configuration changed')
        except (OSError, subprocess.CalledProcessError, FixError):
            print('[!] Apply failed; restoring original configuration.', file=sys.stderr)
            atomic_write(conf, original, bk / 'etc/ca-certificates.conf')
            try:
                rebuild(command)
            except (OSError, subprocess.CalledProcessError):
                print('[!] Recovery rebuild failed; repair with backup at ' + str(bk), file=sys.stderr)
            raise
        print('[+] Selected policy verified in configuration, CA bundle and certificate directory.')
        print('[!] This audits only the system store. Separate app/container/certifi stores require their own updates.')
        return 0


def main():
    args = parse_args()
    if sys.platform != 'linux':
        print('ERROR: only Debian/Ubuntu Linux is supported; no Windows/macOS stores were changed.', file=sys.stderr)
        return 3
    try:
        return execute(args)
    except (FixError, OSError, subprocess.CalledProcessError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
PYTHON
