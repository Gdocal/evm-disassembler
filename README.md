# EVM Bytecode Disassembler

## Requirement
 * Python 3.6
 * Z3 (tested with 4.8.8):
   * Download binary from https://github.com/Z3Prover/z3/releases
   * Set environment variables, where `Z3` is the path to the downloaded binary directory
     ```
     export PATH=$Z3/bin:$PATH
     export PYTHONPATH=$Z3/bin/python:$PYTHONPATH
     export DYLD_LIBRARY_PATH=$Z3/bin:$DYLD_LIBRARY_PATH  (Mac)
     export LD_LIBRARY_PATH=$Z3/bin:$LD_LIBRARY_PATH      (Linux)
     ```
 * Eliot (for profiling): See more https://eliot.readthedocs.io/en/stable/quickstart.html
   * Quick install
     ```
     $ pip install eliot eliot-tree
     ```

#### Quick test for installation

```
$ bash run.sh
```

## Run

#### Generate final states

Run:
```
$ python3.6 -O <function>.py
```

Examples of `<function>.py` are:
* For running a single function: stakewise/Solos.addDeposit.py
* For running the fallback function: stakewise/Solos.fallback.py

The above command will print out all the final states (i.e., the leaf nodes) of the execution tree.

#### Generate full execution tree

To generate intermediate states, run the above command without the `-O` flag.
It will generate `out.json` file in the current directory.
(The json file name can be specified differently in the `<function>.py` file.)

#### View single execution path

Run:
```
$ python3.6 pp.py out.json <leaf-node-number>
```

This will print out the path from the root to the given (leaf) node in the execution tree.
The node number can be found in `out.json`.
(I plan to have the node number included in the final states.)

#### Limitations

For now, it doesn't work or needs extra preconditions if the function takes arrays as input or has loops in the body.
