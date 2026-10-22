#!/usr/bin/env python3
"""seed-data-grow.py asks diskutil for the attached seed's APFS container right after hdiutil attach -nomount; the container is probed
asynchronously and on a fresh runner it is not listed yet. Poll for up to a minute, and show the disks when it never appears."""
import sys
p = sys.argv[1]
s = open(p).read()
old = """            listing = plistlib.loads(subprocess.check_output(['diskutil', 'apfs', 'list', '-plist']))
            container = None
            for entry in listing['Containers']:
                if any(s['DeviceIdentifier'] == store for s in entry.get('PhysicalStores', [])):
                    container = entry['ContainerReference']
"""
new = """            import time
            print('hdiutil attached:', attached, 'store:', store)
            ids = set(re.findall(r'/dev/(disk\d+)', attached)) | {store}
            container = None
            for _ in range(60):
                listing = plistlib.loads(subprocess.check_output(['diskutil', 'apfs', 'list', '-plist']))
                for entry in listing['Containers']:
                    stores = [x['DeviceIdentifier'] for x in entry.get('PhysicalStores', [])]
                    if ids & set(stores) or entry['ContainerReference'] in ids:
                        container = entry['ContainerReference']
                        store = re.sub(r's\d+$', '', stores[0]) if stores else store    # the whole-disk node that hdiutil detaches
                if container:
                    break
                time.sleep(1)
            if not container:
                subprocess.run(['diskutil', 'list'])
                subprocess.run(['diskutil', 'apfs', 'list'])
"""
assert s.count(old) == 1, 'seed-data-grow.py changed'
open(p, 'w').write(s.replace(old, new))
