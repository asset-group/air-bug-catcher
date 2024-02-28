# Auto Exploiter

# Setup

## Symbolic Files

As this tool is relying on WDissector to dissect packets, some binary and configuration files are required to be present in the directory. Symbolic links are recommended for this purpose.

- Binary files from WDissector repository folder `wdissector/bin/`, note that this `bin` folder will be present after compilation
    1. `bin/`
- WDissector bindings from WDissector repository folder `wdissector/bindings/python/`
    1. `wdissector_wrap.cxx`
    2. `wdissector.i`
    3. `wdissector.py`
- Configuration files from WDissector repository folder `wdissector/configs/`
    1. `configs/`
