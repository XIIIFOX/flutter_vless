#!/usr/bin/env python3
"""File/process-boundary guards; never compile or execute Go/Core."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_xdrive_idle_core_runtime as runner


class IdleDiagnosticGuards(unittest.TestCase):
    def test_remote_authority_requires_both_flags(self):
        for env in [{}, {'CI': 'true'}, {'GITHUB_ACTIONS': 'true'}, {'CI': 'false', 'GITHUB_ACTIONS': 'true'}]:
            self.assertFalse(runner.runtime_authorized(env))
        self.assertTrue(runner.runtime_authorized({'CI': 'true', 'GITHUB_ACTIONS': 'true'}))

    def test_local_refusal_precedes_files_or_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'must-not-exist'
            with patch.dict(os.environ, {}, clear=True), patch.object(runner.subprocess, 'run', side_effect=AssertionError('process forbidden')), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    runner.main(['--run-runtime', '--evidence', str(output)])
            self.assertFalse(output.exists())

    def test_failure_requires_exact_clean_test_assertion(self):
        row = {'name': 'idle-runtime', 'exit_code': 1, 'process_exit_code': 1, 'timed_out': False,
               'output_closed': True, 'output_eof': True, 'output_errors': []}
        text = f'--- FAIL: {runner.TEST}\n{runner.ASSERTION}\nFAIL\n'
        self.assertTrue(runner.reproduced_failure([row], text))
        for key, value in [('name', 'idle-compile'), ('exit_code', 124), ('process_exit_code', -9),
                           ('timed_out', True), ('output_closed', False), ('output_eof', False), ('output_errors', ['sink'])]:
            self.assertFalse(runner.reproduced_failure([dict(row, **{key: value})], text))
        self.assertFalse(runner.reproduced_failure([row], 'FAIL'))


if __name__ == '__main__':
    unittest.main()
