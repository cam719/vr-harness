"""gstcodeql: GStreamer CodeQL-hypothesis + PoC-reproduction harness on vrcore.

- reproduce  : replay the known PoC files under ASAN (confirmation / liveness).
- hypothesis : turn a CodeQL finding (a suspected unchecked field) into targeted
               inputs and record which values fault -- discovery of NEW bugs.

Transport = a GStreamer ASAN pipeline subprocess; oracle = sanitizer/crash in its
output; everything recorded N-of-N on the vrcore timeline. Non-destructive.
"""
