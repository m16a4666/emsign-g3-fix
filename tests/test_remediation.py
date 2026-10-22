"""Offline regression tests using public root certificates, never the host store."""
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / 'tests/fixtures'
core = types.ModuleType('emsign_core')
script = (REPO / 'fix-emsign-g3only.sh').read_text(encoding='utf-8')
exec(compile(script.split("<<'PYTHON'\n", 1)[1].rsplit('\nPYTHON', 1)[0],
             str(REPO / 'fix-emsign-g3only.sh'), 'exec'), core.__dict__)


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'usr/share/ca-certificates/mozilla'
        self.certs = self.root / 'etc/ssl/certs'
        self.local = self.root / 'usr/local/share/ca-certificates'
        for directory in (self.source, self.certs, self.local):
            directory.mkdir(parents=True)
        self.conf = self.root / 'etc/ca-certificates.conf'
        self.bundle = self.certs / 'ca-certificates.crt'
        self.backups = self.root / 'backups'
        self.original = b'# administrator policy\n\n'
        for name in ('G3', 'C1', 'C3', 'G1', 'AAA', 'unrelated'):
            (self.source / (name + '.crt')).write_bytes((FIXTURES / (name + '.crt')).read_bytes())
            self.original += ('mozilla/' + name + '.crt\n').encode()
        self.conf.write_bytes(self.original)
        self.regenerate(None)
        self.rebuild = patch.object(core, 'rebuild', side_effect=self.regenerate).start()
        self.addCleanup(patch.stopall)
        patch.object(core.os, 'geteuid', return_value=0, create=True).start()
        # Directory flock is POSIX only; tested with the actual launcher in Linux CI.
        patch.object(core, 'lock', return_value=contextlib.nullcontext()).start()
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def regenerate(self, command):
        result = b''
        for line in self.conf.read_text().splitlines():
            if line and not line.startswith(('#', '!')):
                path = self.root / 'usr/share/ca-certificates' / line
                if path.exists():
                    result += path.read_bytes()
        for path in self.local.rglob('*.crt'):
            result += path.read_bytes()
        self.bundle.write_bytes(result)

    def run_fix(self, *options):
        args = core.parse_args(['--backup-dir', str(self.backups), *options])
        return core.execute(args, root=self.root, updater='/mock/update-ca-certificates')

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.read_bytes(), p.stat().st_mtime_ns)
                for p in self.root.rglob('*') if p.is_file()}

    def test_real_certificate_and_spki_fingerprints(self):
        for name in ('G3', 'C1', 'C3', 'G1', 'AAA'):
            self.assertEqual(core.identities((FIXTURES / (name + '.crt')).read_bytes()), {name})
        self.assertEqual(core.identities((FIXTURES / 'unrelated.crt').read_bytes()), set())

    def test_default_blocks_three_and_preserves_g1_aaa(self):
        self.assertEqual(self.run_fix(), 0)
        self.assertEqual(core.read_ids(self.bundle), {'G1', 'AAA'})
        self.assertIn(b'mozilla/G1.crt\n', self.conf.read_bytes())
        self.assertIn(b'mozilla/AAA.crt\n', self.conf.read_bytes())
        self.assertEqual(self.conf.read_bytes().count(b'!'), 3)

    def test_admin_disabled_g1_stays_disabled(self):
        self.conf.write_bytes(self.original.replace(b'mozilla/G1.crt', b'!mozilla/G1.crt'))
        self.run_fix()
        self.assertIn(b'!mozilla/G1.crt', self.conf.read_bytes())
        self.assertNotIn('G1', core.read_ids(self.bundle))

    def test_polluted_configuration_never_reenables_roots(self):
        data = self.original.replace(b'mozilla/', b'!mozilla/')
        self.conf.write_bytes(data)
        # Keep one unrelated CA trusted so the generated bundle stays valid.
        self.conf.write_bytes(data.replace(b'!mozilla/unrelated', b'mozilla/unrelated'))
        self.run_fix()
        self.assertIn(b'!mozilla/G1.crt', self.conf.read_bytes())
        self.assertEqual(core.read_ids(self.bundle), set())

    def test_strict_also_blocks_g1_and_aaa(self):
        self.assertEqual(self.run_fix('--strict'), 0)
        self.assertEqual(core.read_ids(self.bundle), set())

    def test_rerun_changes_no_bytes_mtimes_or_backups(self):
        self.run_fix()
        before = self.snapshot()
        self.rebuild.reset_mock()
        self.assertEqual(self.run_fix(), 0)
        self.assertEqual(before, self.snapshot())
        self.rebuild.assert_not_called()

    def test_check_and_dry_run_are_readonly_and_do_not_need_root(self):
        for flag in ('--check', '--verify', '--dry-run'):
            with patch.object(core.os, 'geteuid', return_value=1000):
                before = self.snapshot()
                self.assertEqual(self.run_fix(flag), 1)
                self.assertEqual(before, self.snapshot())
        self.rebuild.assert_not_called()

    def test_check_passes_after_apply(self):
        self.run_fix()
        self.assertEqual(self.run_fix('--check'), 0)
        self.assertEqual(self.run_fix('--strict', '--check'), 1)

    def test_missing_roots_not_added_or_required(self):
        self.conf.write_bytes(b'# roots already removed\nmozilla/unrelated.crt\n')
        for path in self.source.glob('*.crt'):
            if path.name != 'unrelated.crt':
                path.unlink()
        self.regenerate(None)
        before = self.snapshot()
        self.assertEqual(self.run_fix(), 0)
        self.assertEqual(before, self.snapshot())

    def test_normalize_duplicate_bangs_crlf_case_and_no_final_newline(self):
        data = b'# keep\r\n  !!mozilla/emSign_ECC_Root_CA_-_G3.crt \r\nmozilla/emSign_ECC_Root_CA_-_G3.crt'
        result, changes = core.normalized(data, self.source.parent, {'G3'})
        self.assertEqual(result, b'# keep\r\n!mozilla/emSign_ECC_Root_CA_-_G3.crt\r\n!mozilla/emSign_ECC_Root_CA_-_G3.crt\n')
        self.assertEqual(len(changes), 2)
        self.assertEqual(core.normalized(result, self.source.parent, {'G3'})[0], result)

    def test_local_override_refused_before_writes(self):
        (self.local / 'renamed.crt').write_bytes((FIXTURES / 'G3.crt').read_bytes())
        before = self.snapshot()
        with self.assertRaisesRegex(core.FixError, 'local trust override'):
            self.run_fix()
        self.assertEqual(before, self.snapshot())
        self.rebuild.assert_not_called()

    def test_renamed_source_is_blocked_by_content(self):
        self.run_fix()
        (self.source / 'alias.crt').write_bytes((FIXTURES / 'G3.crt').read_bytes())
        self.conf.write_bytes(self.conf.read_bytes() + b'mozilla/alias.crt\n')
        self.regenerate(None)
        self.run_fix()
        self.assertIn(b'!mozilla/alias.crt', self.conf.read_bytes())
        self.assertNotIn('G3', core.read_ids(self.bundle))

    def test_stale_bundle_regenerated_with_no_configuration_change(self):
        self.run_fix()
        self.bundle.write_bytes(self.bundle.read_bytes() + (FIXTURES / 'G3.crt').read_bytes())
        conf = self.conf.read_bytes()
        self.assertEqual(self.run_fix(), 0)
        self.assertEqual(conf, self.conf.read_bytes())
        self.assertNotIn('G3', core.read_ids(self.bundle))

    def test_update_failure_restores_configuration_and_reports_failure(self):
        self.rebuild.side_effect = [subprocess.CalledProcessError(1, 'update-ca-certificates'), None]
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_fix()
        self.assertEqual(self.conf.read_bytes(), self.original)
        self.assertEqual(self.rebuild.call_count, 2)

    def test_verification_failure_restores_configuration(self):
        self.rebuild.side_effect = None  # leave old bundle unchanged
        with self.assertRaisesRegex(core.FixError, 'post-update verification'):
            self.run_fix()
        self.assertEqual(self.conf.read_bytes(), self.original)

    def test_backup_failure_makes_no_changes(self):
        self.backups.write_text('not a directory')
        before = self.snapshot()
        with self.assertRaises(OSError):
            self.run_fix()
        self.assertEqual(before, self.snapshot())
        self.rebuild.assert_not_called()

    def test_rollback_restores_exact_conf_and_regenerates_bundle(self):
        self.run_fix()
        bk = next(self.backups.iterdir())
        self.assertEqual((bk / 'etc/ca-certificates.conf').read_bytes(), self.original)
        self.assertTrue((bk / 'etc/ssl/certs/ca-certificates.crt').is_file())
        self.assertEqual(self.run_fix('--rollback', str(bk)), 0)
        self.assertEqual(self.conf.read_bytes(), self.original)
        self.assertEqual(core.read_ids(self.bundle), {'G3', 'C1', 'C3', 'G1', 'AAA'})
        self.assertEqual(len(list(self.backups.iterdir())), 2)

    def test_invalid_backup_refused_without_changes(self):
        before = self.snapshot()
        with self.assertRaisesRegex(core.FixError, 'backup configuration missing'):
            self.run_fix('--rollback', str(self.root / 'missing'))
        self.assertEqual(before, self.snapshot())

    def test_empty_bundle_not_mistaken_for_success(self):
        self.bundle.write_bytes(b'')
        with self.assertRaisesRegex(core.FixError, 'invalid CA bundle'):
            self.run_fix('--check')

    def test_invalid_pem_and_der_are_reported(self):
        for data in (b'-----BEGIN CERTIFICATE-----\nbroken',
                     b'-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----',
                     b'-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----'):
            with self.assertRaises(core.FixError):
                core.identities(data)

    def test_paths_cannot_escape_source_directory(self):
        for path in (b'../G3.crt\n', b'/tmp/G3.crt\n'):
            with self.assertRaisesRegex(core.FixError, 'unsafe certificate path'):
                core.normalized(path, self.source, {'G3'})

    def test_apply_requires_root_before_writes(self):
        with patch.object(core.os, 'geteuid', return_value=1000):
            before = self.snapshot()
            with self.assertRaisesRegex(core.FixError, 'as root'):
                self.run_fix()
            self.assertEqual(before, self.snapshot())

    def test_residual_hash_directory_certificate_is_detected(self):
        self.run_fix()
        (self.certs / 'cafebabe.0').write_bytes((FIXTURES / 'G3.crt').read_bytes())
        self.assertEqual(self.run_fix('--check'), 1)
        with self.assertRaisesRegex(core.FixError, 'post-update verification'):
            self.run_fix()


if __name__ == '__main__':
    unittest.main()
