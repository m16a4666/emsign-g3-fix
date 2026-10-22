"""Run only in a disposable Debian/Ubuntu container: modifies its trust store."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

if os.environ.get('EMSIGN_DISPOSABLE_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    sys.exit('Refusing integration test outside an explicitly marked disposable Docker container.')

repo = Path(__file__).resolve().parents[1]
script = str(repo / 'fix-emsign-g3only.sh')
source = Path('/usr/share/ca-certificates/emsign-regression')
source.mkdir()
conf = Path('/etc/ca-certificates.conf')
fixtures = repo / 'tests/fixtures'
for path in fixtures.glob('*.crt'):
    shutil.copy2(path, source / path.name)
with conf.open('ab') as stream:
    stream.write(b'\n# Offline regression fixtures\n')
    for path in sorted(source.glob('*.crt')):
        stream.write(('emsign-regression/' + path.name + '\n').encode())
subprocess.run(['update-ca-certificates', '--fresh'], check=True)
original = conf.read_bytes()
backups = Path('/var/backups/emsign-integration')


def run(*args, expected=0):
    result = subprocess.run(['bash', script, '--backup-dir', str(backups), *args])
    assert result.returncode == expected, (args, result.returncode, expected)


run('--check', expected=1)
run('--dry-run', expected=1)
assert conf.read_bytes() == original and not backups.exists()
run()
first = next(backups.iterdir())
run('--check')
before = (conf.stat().st_mtime_ns, Path('/etc/ssl/certs/ca-certificates.crt').stat().st_mtime_ns)
run()
assert before == (conf.stat().st_mtime_ns, Path('/etc/ssl/certs/ca-certificates.crt').stat().st_mtime_ns)
assert len(list(backups.iterdir())) == 1
run('--strict', '--check', expected=1)
run('--strict')
run('--strict', '--verify')
# Hash-addressed CApath and bundle must both be clear of all five fixtures.
sys.path.insert(0, str(repo / 'tests'))
from test_remediation import core  # noqa: E402
active, _ = core.audit(Path('/etc/ssl/certs/ca-certificates.crt'),
                       Path('/etc/ssl/certs'), Path('/usr/local/share/ca-certificates'))
assert not active & {'G3', 'C1', 'C3', 'G1', 'AAA'}
run('--rollback', str(first))
assert conf.read_bytes() == original
run('--check', expected=1)
print('PASS: real update-ca-certificates, CApath, idempotence, strict policy and rollback')
