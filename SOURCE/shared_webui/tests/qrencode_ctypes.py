#!/usr/bin/env python3
"""Test-workstation stand-in for the `qrencode -t SVG -o -` CLI.

Encodes with the REAL libqrencode shared library (libqrencode.so.4) through
ctypes, because the CLI package is not installed on this test host. The panel
on a VPS uses the distribution /usr/bin/qrencode. SBOX_TEST_QR_EVIL=1 emits a
script-bearing SVG to prove the panel refuses unexpected QR output.
"""
import ctypes, os, sys

class QRcode(ctypes.Structure):
    _fields_ = [('version', ctypes.c_int), ('width', ctypes.c_int), ('data', ctypes.POINTER(ctypes.c_ubyte))]

def main():
    if sys.argv[1:] != ['-t', 'SVG', '-o', '-']:
        sys.exit('usage: qrencode -t SVG -o -')
    text = sys.stdin.read().encode()
    if os.environ.get('SBOX_TEST_QR_EVIL'):
        print('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'); return
    lib = ctypes.CDLL('libqrencode.so.4')
    lib.QRcode_encodeString.restype = ctypes.POINTER(QRcode)
    lib.QRcode_encodeString.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    code = lib.QRcode_encodeString(text, 0, 0, 2, 1)  # QR_ECLEVEL_L, QR_MODE_8, case-sensitive (qrencode CLI defaults)
    if not code: sys.exit('encoding failed')
    w = code.contents.width; data = code.contents.data; margin = 4; size = w + 2 * margin
    rects = ['<rect x="%d" y="%d" width="1" height="1"/>' % (x + margin, y + margin) for y in range(w) for x in range(w) if data[y * w + x] & 1]
    lib.QRcode_free(code)
    sys.stdout.write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges">'
                     '<rect width="100%%" height="100%%" fill="#ffffff"/><g fill="#000000">%s</g></svg>\n' % (size, size, size * 8, size * 8, ''.join(rects)))

if __name__ == '__main__':
    main()
