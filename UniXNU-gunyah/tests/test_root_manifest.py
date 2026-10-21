#!/usr/bin/env python3
"""Reject mismatched manifests/disks and forged or missing runtime GUID evidence."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--image',type=Path,required=True)
p.add_argument('--manifest',type=Path,required=True)
args=p.parse_args()
root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('runner',root/'tools/run-xnu-boot.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
data=args.image.read_bytes();manifest=json.loads(args.manifest.read_text())
uuid=manifest['partition']['uuid'];boot='rd=gvblk0 gunyah-root-partuuid='+uuid
binding=r.validate_root_manifest(manifest,data,boot)
assert binding['start_sector']==2048 and binding['sectors']==65536
cases=[]
for key,value in [('disk_sha256','0'*64),('source_sha256','0'*64),('disk_sectors',1),('sector_size',4096)]:
    m=copy.deepcopy(manifest);m[key]=value;cases.append((m,data,boot))
for key,value in [('start_sector',0),('sectors',65535),('index',2),('uuid','11111111-2222-3333-4444-555555555555')]:
    m=copy.deepcopy(manifest);m['partition'][key]=value;cases.append((m,data,boot))
cases += [(manifest,bytes([data[0]^1])+data[1:],boot),
          (manifest,data,boot+' gunyah-root-start=2048 gunyah-root-sectors=65536'),
          (manifest,data,boot+' gunyah-root-partuuid='+uuid)]
for m,d,b in cases:
    try:r.validate_root_manifest(m,d,b)
    except ValueError:pass
    else:raise AssertionError('Mismatched manifest accepted')
log=f'GUNYAH-GPT: selected uuid={uuid} index=1 start=2048 sectors=65536 copies=2 crc=PASS\nGUNYAH-BSD: window start=2048 sectors=65536 disk_sectors=69632 explicit=0\n'
assert r.disk_window_checks(log,boot,len(data))['gpt_selection_verified']
for value in ('',log+log,log.replace('copies=2','copies=1'),log.replace(uuid,'11111111-2222-3333-4444-555555555555'),log+'GUNYAH-BSD: failure=gpt-header'):
    assert not r.disk_window_checks(value,boot,len(data))['gpt_selection_verified']
print('Root manifest: 11 mismatches rejected; valid GUID and 5 bad runtime logs checked')
