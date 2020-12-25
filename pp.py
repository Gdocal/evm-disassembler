#!/usr/bin/env python3.6

import sys
import json
from typing import List, Dict, Tuple, Any

def pp(filename: str, last: int):
    with open(filename) as f:
        steps: Dict[int,Dict[str,Any]] = json.load(f)
    idx: int = last
    out: List[str] = []
    while idx > 0:
        out.append(steps[str(idx)]['exec'])
        idx = int(steps[str(idx)]['parent'])
    idx = len(out)
    while idx > 0:
        idx -= 1
        print(out[idx])

if __name__ == '__main__':
    pp(sys.argv[1], int(sys.argv[2]))
