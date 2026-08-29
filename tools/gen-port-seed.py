#!/usr/bin/env python3
"""Regenerate registry.d/resolvd-port.reg: the tcp,udp:53 reservation.

Same descriptor shape as pkm/tools/gen-port-reservations-seed.py (owner and
group SYSTEM; one ACCESS_ALLOWED ACE per grantee carrying PORT_BIND |
READ_CONTROL). Grantees: SYSTEM, and resolvd's service SID — S-1-5-80 with
five little-endian u32 sub-authorities from SHA-1 of the upper-cased
UTF-16LE service name, as peinit derives it (peinit/src/security/service_sid.rs).
"""
import hashlib, json, os, struct, sys

def sid(auth, subs):
    return bytes([1, len(subs)]) + auth.to_bytes(6, 'big') + b''.join(struct.pack('<I', s) for s in subs)

SYSTEM = sid(5, [18])
PORT_BIND, READ_CONTROL = 0x1, 0x20000

def service_sid(name):
    h = hashlib.sha1(name.upper().encode('utf-16-le')).digest()
    subs = [struct.unpack('<I', h[i:i + 4])[0] for i in range(0, 20, 4)]
    return sid(5, [80] + subs), 'S-1-5-80-' + '-'.join(map(str, subs))

def ace(s, mask):
    return bytes([0, 0]) + struct.pack('<H', 8 + len(s)) + struct.pack('<I', mask) + s

def sd(aces):
    body = b''.join(aces)
    acl = bytes([2, 0]) + struct.pack('<HHH', 8 + len(body), len(aces), 0) + body
    owner, group = 20, 20 + len(SYSTEM)
    hdr = bytes([1, 0]) + struct.pack('<H', 0x8004) + struct.pack('<IIII', owner, group, 0, group + len(SYSTEM))
    return hdr + SYSTEM + SYSTEM + acl

def main():
    svc, svcstr = service_sid('resolvd')
    out = os.path.join(os.path.dirname(__file__), '..', 'registry.d', 'resolvd-port.reg')
    doc = json.load(open(out))
    values = doc['keys'][-1]['values']
    values[0]['data'] = sd([ace(SYSTEM, PORT_BIND | READ_CONTROL), ace(svc, PORT_BIND | READ_CONTROL)]).hex()
    doc['_comment'] = [l if 'S-1-5-80-' not in l else '  ' + svcstr for l in doc['_comment']]
    json.dump(doc, open(out, 'w'), indent=2); open(out, 'a').write('\n')
    print(svcstr)

if __name__ == '__main__':
    sys.exit(main())
