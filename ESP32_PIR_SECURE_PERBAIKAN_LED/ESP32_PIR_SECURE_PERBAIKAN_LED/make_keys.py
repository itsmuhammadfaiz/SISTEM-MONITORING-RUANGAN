#!/usr/bin/env python3
"""Provision unique classroom-demo keys. Never upload generated secrets.h files to a public repository."""
from pathlib import Path
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

root = Path(__file__).resolve().parent
shared = secrets.token_bytes(16)
priv = ec.generate_private_key(ec.SECP256R1())
private = priv.private_numbers().private_value.to_bytes(32, 'big')
public = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
assert len(public) == 65

def array(name, values):
    rows = [', '.join(f'0x{x:02X}' for x in values[i:i+12]) for i in range(0,len(values),12)]
    return 'static const uint8_t ' + name + f'[{len(values)}] = {{\n    ' + ',\n    '.join(rows) + '\n};\n'

header = '#pragma once\n#include <stdint.h>\n// KUNCI RAHASIA — JANGAN DIUNGGAH KE GITHUB / LAPORAN\n'
tx = header + array('TINYJAMBU_KEY',shared) + array('ECDSA_PRIVATE_KEY',private)
rx = header + array('TINYJAMBU_KEY',shared) + array('ECDSA_PUBLIC_KEY',public)
(root/'TRANSMITTER_SECURE'/'secrets.h').write_text(tx,encoding='utf-8')
(root/'RECEIVER_SECURE'/'secrets.h').write_text(rx,encoding='utf-8')
print('Kunci dibuat: TRANSMITTER_SECURE/secrets.h & RECEIVER_SECURE/secrets.h')
print('Simpan file secara pribadi. Generate ulang jika salah satu kunci bocor.')
