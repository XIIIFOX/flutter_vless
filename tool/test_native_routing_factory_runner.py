#!/usr/bin/env python3
"""File-only guards for artifact selection and prerequisite evidence."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('factory_guard_subject',ROOT/'tool/test_native_routing_factory.py')
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


class FactoryRunnerTest(unittest.TestCase):
    def test_actual_factory_never_enters_pure_selection(self):
        text='\n'.join(['TestNativeRoutingCandidateMissingRuntime',runner.RUNTIME,'TestNativeRoutingDefaultArtifactRefuses'])
        self.assertEqual(runner.selected(text,False),['TestNativeRoutingCandidateMissingRuntime','TestNativeRoutingDefaultArtifactRefuses'])
        with self.assertRaises(ValueError):runner.selected(text,True)
        self.assertEqual(runner.selected('TestNativeRoutingOptionalArtifactCapability',True),['TestNativeRoutingOptionalArtifactCapability'])

    def test_runtime_refusal_precedes_files_or_children(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence=Path(directory)/'must-not-exist'
            with patch.object(runner,'EVIDENCE',evidence),patch.dict(os.environ,{'CI':'false','GITHUB_ACTIONS':'false'}),patch.object(runner.core_runner,'checked') as child,contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):runner.main(['--run-runtime'])
            child.assert_not_called();self.assertFalse(evidence.exists())

    def check_receipt(self,change=None):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);core=root/'Core';core.mkdir()
            (core/'fixture.go').write_text('package fixture\n')
            snapshot={'overlay.go':'fixed-source-hash'}
            report={key:True for key in ['success','source_snapshot_unchanged','copied_source_unchanged','module_cache_source_unchanged']}
            report.update(source_sha256=dict(snapshot),copied_tree_sha256=runner.tree_hash(core))
            if change:change(report,core)
            (root/'result.json').write_text(json.dumps(report))
            with patch.object(runner.core_runner,'source_snapshot',return_value=snapshot):
                return runner.checked_core(root)

    def test_complete_matching_receipt_is_accepted(self):
        _,report=self.check_receipt();self.assertTrue(report['success'])

    def test_partial_or_stale_receipt_is_refused(self):
        for snapshot in [{},{'overlay.go':'old'},{'overlay.go':'fixed-source-hash','extra.go':'unexpected'}]:
            with self.subTest(snapshot=snapshot),self.assertRaises(ValueError):
                self.check_receipt(lambda report,core:report.update(source_sha256=snapshot))

    def test_failed_prerequisite_is_refused(self):
        for key in ['success','source_snapshot_unchanged','copied_source_unchanged','module_cache_source_unchanged']:
            with self.subTest(key=key),self.assertRaises(ValueError):
                self.check_receipt(lambda report,core:report.update({key:False}))

    def test_changed_core_copy_is_refused(self):
        with self.assertRaises(ValueError):
            self.check_receipt(lambda report,core:(core/'fixture.go').write_text('changed'))


if __name__=='__main__':unittest.main()
