#!/usr/bin/env python3
"""Make UniXNU's GitHub API fetches authenticated (anonymous runners hit the rate limit)."""
import sys
p = sys.argv[1]
s = open(p).read()
hook = ("\nimport os as _os, urllib.request as _u\n"
        "if _os.environ.get('GITHUB_TOKEN'):\n"
        "    _o = _u.build_opener(); _o.addheaders = [('Authorization', 'Bearer ' + _os.environ['GITHUB_TOKEN'])]; _u.install_opener(_o)\n")
assert 'import urllib.request' in s
s = s.replace('import urllib.request', 'import urllib.request' + hook, 1)
open(p, 'w').write(s)
