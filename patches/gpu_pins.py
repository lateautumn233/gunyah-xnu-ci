#!/usr/bin/env python3
"""Print one pinned value of UniXNU's GPU inputs: gpu_pins.py mesa-commit|mesa-dirs|mesa-patches|m2v-commit TREE"""
import json
import sys
from pathlib import Path

what, tree = sys.argv[1], Path(sys.argv[2])
adreno = json.loads((tree / 'scripts/data/adreno-compiler-inputs.json').read_text())
m2v = json.loads((tree / 'scripts/data/gpu-metal-vulkan-inputs.json').read_text())
print({'mesa-commit': lambda: adreno['mesa']['commit'],
       'mesa-dirs': lambda: ' '.join(adreno['mesa']['sparse_directories']),
       'mesa-patches': lambda: ' '.join(adreno['patches']),
       'm2v-commit': lambda: m2v['translator']['commit']}[what]())
