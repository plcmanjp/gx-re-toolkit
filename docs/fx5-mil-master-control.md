# FX5 MIL master control scope

The decoder recognizes the exact nonpulse `MC N M` and `MCR N` MIL signatures
with signed 16-bit nesting operands. `N` remains outside the generic scalar
device set. Other operand families, widths, pulse forms, raw metadata and
unknown signatures remain unmined.

The nesting index is limited to `N0` through `N14`, as documented in the
[MELSEC iQ-F FX5 Programming Manual, section 6.5](https://dl.mitsubishielectric.com/dl/fa/document/manual/plcf/jy997d55801/jy997d55801aa.pdf).
Synthetic tests cover both endpoints, out-of-range indices, exact operand
continuation, partial preservation and unchanged input bytes.

These tests demonstrate offline parser behavior. They do not establish actual
N14 execution, a nested ladder's behavior, Simulator acceptance or physical PLC
acceptance. No private project, official export or vendor document is included.
