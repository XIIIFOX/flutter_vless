"""File-only patch guards. No Go/Core/build/network is executed."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('geodata_lifetime_patch',Path(__file__).with_name('geodata_lifetime_patch.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class GeoDataPatchGuards(unittest.TestCase):
    def fixture(self, root):
        for name in module.PATHS:
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True)
            p.write_text('\n\n'.join(before for path,before,_ in module.replacements() if path==name)+'\n')
        return {name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in module.PATHS}
    def test_rejects_changed_actual_pin_before_any_callback(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.fixture(root);called=[]
            with self.assertRaisesRegex(ValueError,'Pinned GeoDAT source mismatch'):
                module.apply(root,lambda *args:called.append(args))
            self.assertEqual(called,[])
    def test_checks_all_boundaries_before_first_write(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);hashes=self.fixture(root);name,before,_=module.replacements()[-1]
            p=root/name;p.write_text(p.read_text().replace(before,'drift'))
            hashes[name]=hashlib.sha256(p.read_bytes()).hexdigest();initial={n:(root/n).read_bytes() for n in module.PATHS};called=[]
            with patch.dict(module.UPSTREAM_SHA256,hashes,clear=True),self.assertRaisesRegex(ValueError,'boundary changed'):
                module.apply(root,lambda *args:called.append(args))
            self.assertEqual(called,[]);self.assertEqual(initial,{n:(root/n).read_bytes() for n in module.PATHS})
    def test_applies_only_owned_lifetime_and_cancels_before_wait(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);hashes=self.fixture(root)
            def replace(name,before,after):
                p=root/name;s=p.read_text();self.assertEqual(s.count(before),1);p.write_text(s.replace(before,after))
            with patch.dict(module.UPSTREAM_SHA256,hashes,clear=True):module.apply(root,replace)
            body=(root/'app/geodata/geodata.go').read_text();download=(root/'app/geodata/download.go').read_text()
            close=body[body.index('func (g *Instance) Close()'):]
            self.assertLess(close.index('g.cancelDownload()'),close.index('<-g.tasker.Stop().Done()'))
            self.assertIn('context.WithCancel(ctx)',body);self.assertIn('newDownloader(downloadCtx,',body)
            self.assertIn('d.httpsClient.CloseIdleConnections()',download)
            self.assertNotIn('http.DefaultTransport',body+download)
            self.assertNotIn('context.Background()',body+download)
    def test_rejects_symlink_even_when_contents_match(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);hashes=self.fixture(root);first=root/module.PATHS[0];copy=root/'outside';copy.write_bytes(first.read_bytes());first.unlink();first.symlink_to(copy);called=[]
            with patch.dict(module.UPSTREAM_SHA256,hashes,clear=True),self.assertRaisesRegex(ValueError,'source mismatch'):
                module.apply(root,lambda *args:called.append(args))
            self.assertEqual(called,[])

if __name__=='__main__':unittest.main()
