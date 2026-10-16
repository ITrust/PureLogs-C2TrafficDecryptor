#!/usr/bin/env python3

###################### Itrust CERT ######################
#
# @SamuelRaebisch - @AlexisDuverneix
#
# Ref: https://www.itrust.fr/purelogs-stealer-analyse-malware

"""
Videcoded script that decrypts the C2 traffic of PureLogs Stealer stage 3 (tray01.exe)
directly from a pcap capture.

AES-128 key statically extracted from the binary: <PrivateImplementationDetails>
field at RVA 0x2048 (file offset 0x248), loaded by InitializeArray in
map42..cctor and stored in tx67.axis340 (AES-128-CBC / PKCS7, line 4244).

Frame:   [ length : uint32 LE ][ IV : 16 bytes cleartext ][ AES-128-CBC(payload) ]
Payload: custom serialization, 1-byte tag + data.
"""
import argparse
import struct
import sys
from collections import defaultdict

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_HEX = '7B41C330B576FA8D0CE909C2B1E4D150'
KEY_FILE_OFFSET = 0x248

# ---------------------------------------------------------------- pcap

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_NULL = 0


def read_pcap(path):
    data = open(path, 'rb').read()
    magic = data[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        endian = '<'
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        endian = '>'
    elif magic == b'\x0a\x0d\x0d\x0a':
        raise SystemExit("pcapng not supported -- convert it: "
                         "editcap -F pcap in.pcapng out.pcap")
    else:
        raise SystemExit(f"unknown format (magic {magic.hex()})")

    linktype = struct.unpack_from(endian + 'I', data, 20)[0]
    packets, off = [], 24
    while off + 16 <= len(data):
        _, _, caplen, _ = struct.unpack_from(endian + 'IIII', data, off)
        off += 16
        packets.append(data[off:off + caplen])
        off += caplen
    return linktype, packets


def strip_link(frame, linktype):
    """Returns the IP datagram, or None if not IPv4/IPv6."""
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from('>H', frame, 12)[0]
        off = 14
        while ethertype in (0x8100, 0x88A8):          # stacked VLANs
            if len(frame) < off + 4:
                return None
            ethertype = struct.unpack_from('>H', frame, off + 2)[0]
            off += 4
        return frame[off:] if ethertype in (0x0800, 0x86DD) else None
    if linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        proto = struct.unpack_from('>H', frame, 14)[0]
        return frame[16:] if proto in (0x0800, 0x86DD) else None
    if linktype == LINKTYPE_RAW:
        return frame
    if linktype == LINKTYPE_NULL:
        return frame[4:] if len(frame) > 4 else None
    return None


def parse_ip_tcp(pkt):
    """Returns (src, sport, dst, dport, seq, flags, payload) or None."""
    if not pkt:
        return None
    version = pkt[0] >> 4
    if version == 4:
        if len(pkt) < 20:
            return None
        ihl = (pkt[0] & 0x0F) * 4
        if pkt[9] != 6 or len(pkt) < ihl:
            return None
        total = struct.unpack_from('>H', pkt, 2)[0]
        src = '.'.join(str(b) for b in pkt[12:16])
        dst = '.'.join(str(b) for b in pkt[16:20])
        # honor total_length: avoid swallowing Ethernet padding
        body = pkt[ihl:total] if 0 < total <= len(pkt) else pkt[ihl:]
    elif version == 6:
        if len(pkt) < 40 or pkt[6] != 6:
            return None
        src = pkt[8:24].hex(':', 2)
        dst = pkt[24:40].hex(':', 2)
        plen = struct.unpack_from('>H', pkt, 4)[0]
        body = pkt[40:40 + plen] if plen else pkt[40:]
    else:
        return None

    if len(body) < 20:
        return None
    sport, dport, seq = struct.unpack_from('>HHI', body, 0)
    doff = (body[12] >> 4) * 4
    flags = body[13]
    if doff < 20 or len(body) < doff:
        return None
    return src, sport, dst, dport, seq, flags, body[doff:]


class Stream:
    """Unidirectional TCP reassembly, tolerant to retransmissions."""

    def __init__(self):
        self.segments = {}       # seq absolu -> données
        self.isn = None

    def add(self, seq, flags, payload):
        if flags & 0x02:         # SYN: initial sequence number is seq+1
            self.isn = (seq + 1) & 0xFFFFFFFF
        if payload:
            prev = self.segments.get(seq)
            if prev is None or len(payload) > len(prev):
                self.segments[seq] = payload

    def assemble(self):
        """Returns (data, [holes]). Holes are (offset, size)."""
        if not self.segments:
            return b'', []
        base = self.isn if self.isn is not None else min(self.segments)
        rel = sorted(((seq - base) & 0xFFFFFFFF, p) for seq, p in self.segments.items())
        out, holes, cursor = bytearray(), [], 0
        for off, payload in rel:
            if off > cursor:
                holes.append((cursor, off - cursor))
                out.extend(b'\x00' * (off - cursor))
                cursor = off
            end = off + len(payload)
            if end <= cursor:
                continue                      # full retransmission
            out[off:end] = payload
            cursor = max(cursor, end)
        return bytes(out), holes


# ---------------- crypto

def unpad_pkcs7(pt):
    """Returns (plaintext, ok). Only strips padding if actually valid."""
    if not pt:
        return pt, False
    n = pt[-1]
    if 1 <= n <= 16 and len(pt) >= n and pt[-n:] == bytes([n]) * n:
        return pt[:-n], True
    return pt, False


def decrypt_frame(body, key):
    if len(body) < 32:
        return None, 'frame too short for IV + 1 block'
    iv, ct = body[:16], body[16:]
    if len(ct) % 16:
        return None, f'unaligned ciphertext ({len(ct)} bytes)'
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt, ok = unpad_pkcs7(dec.update(ct) + dec.finalize())
    return pt, None if ok else 'invalid PKCS7 padding (wrong key?)'


def try_decrypt(body, keys):
    """Tries each known key, returns (plaintext, key used, error)."""
    last = 'no key tried'
    for k in keys:
        pt, err = decrypt_frame(body, k)
        if err is None:
            return pt, k, None
        last = err
    return None, None, last


def extract_session_key(pt):
    """If the plaintext starts with an object whose first member is byte[32],
    returns those 32 bytes -- the new session key after handshake."""
    # 0x54 <count:i32 LE> 0x51 <len:i32 LE = 32> <32 bytes>
    if len(pt) >= 42 and pt[0] == 0x54 and pt[5] == 0x51:
        if struct.unpack_from('<i', pt, 6)[0] == 32:
            return pt[10:42]
    return None


# --------------- payload

TAGS = {
    0x00: 'null', 0x03: 'bool', 0x04: 'char', 0x05: 'sbyte', 0x06: 'byte',
    0x07: 'int16', 0x08: 'uint16', 0x09: 'int32', 0x0A: 'uint32',
    0x0B: 'int64', 0x0C: 'uint64', 0x0D: 'single', 0x0E: 'double',
    0x0F: 'decimal', 0x12: 'string',
    0x50: 'Guid', 0x51: 'byte[]', 0x52: 'IDictionary', 0x53: 'IEnumerable',
    0x54: 'object', 0x55: 'DateTime', 0x56: 'TimeSpan',
}
FIXED = {0x03: 1, 0x04: 2, 0x05: 1, 0x06: 1, 0x07: 2, 0x08: 2, 0x09: 4,
         0x0A: 4, 0x0B: 8, 0x0C: 8, 0x0D: 4, 0x0E: 8, 0x55: 8, 0x56: 8}
CONTAINERS = {0x52: ('dict', 'pairs'), 0x53: ('list', 'elements'),
              0x54: ('object', 'members')}


def deserialize(b, o, depth, out, max_depth=32):
    ind = '  ' * depth
    if o >= len(b):
        out.append(f'{ind}<premature end>')
        return len(b)
    if depth > max_depth:
        out.append(f'{ind}<max depth reached>')
        return len(b)

    tag = b[o]
    o += 1
    name = TAGS.get(tag, f'?0x{tag:02x}')

    if tag == 0x00:
        out.append(f'{ind}null')
        return o

    if tag in FIXED:
        n = FIXED[tag]
        raw = b[o:o + n]
        o += n
        if len(raw) < n:
            out.append(f'{ind}{name} <truncated>')
            return len(b)
        if tag == 0x03:   v = bool(raw[0])
        elif tag == 0x09: v = struct.unpack('<i', raw)[0]
        elif tag == 0x0A: v = struct.unpack('<I', raw)[0]
        elif tag == 0x0B: v = struct.unpack('<q', raw)[0]
        elif tag == 0x55: v = f'DateTime.FromBinary({struct.unpack("<q", raw)[0]})'
        else:             v = raw.hex()
        out.append(f'{ind}{name} = {v}')
        return o

    if tag == 0x12:
        if o + 4 > len(b):
            out.append(f'{ind}string <truncated>')
            return len(b)
        n = struct.unpack_from('<i', b, o)[0]
        o += 4
        if n < 0:
            out.append(f'{ind}string = null')
            return o
        s = b[o:o + n].decode('utf-8', 'replace')
        o += n
        out.append(f'{ind}string({n}) = {s!r}')
        return o

    if tag in (0x50, 0x51):
        if o + 4 > len(b):
            out.append(f'{ind}{name} <truncated>')
            return len(b)
        n = struct.unpack_from('<i', b, o)[0]
        o += 4
        raw = b[o:o + max(n, 0)]
        o += max(n, 0)
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in raw[:32])
        out.append(f'{ind}{name}[{n}] = {raw[:32].hex()}'
                   f'{"..." if n > 32 else ""}  |{printable}|')
        return o

    if tag in CONTAINERS:
        if o + 4 > len(b):
            out.append(f'{ind}{name} <truncated>')
            return len(b)
        n = struct.unpack_from('<i', b, o)[0]
        o += 4
        label, unit = CONTAINERS[tag]
        out.append(f'{ind}{label} ({n} {unit}) {{')
        for _ in range(max(n, 0) * (2 if tag == 0x52 else 1)):
            o = deserialize(b, o, depth + 1, out, max_depth)
        out.append(f'{ind}}}')
        return o

    out.append(f'{ind}<unknown tag 0x{tag:02x} at offset {o - 1}>')
    return len(b)


# ---------------- main logic

def load_key(args):
    if args.key_from_binary:
        with open(args.key_from_binary, 'rb') as f:
            f.seek(args.key_offset)
            key = f.read(16)
        if len(key) != 16:
            raise SystemExit(f'{args.key_from_binary}: could not read 16 bytes at offset 0x{args.key_offset:X}')
        return key
    key = bytes.fromhex(args.key)
    if len(key) != 16:
        raise SystemExit(f'key is {len(key)} bytes, expected 16 (AES-128)')
    return key


def iter_frames(stream):
    """Splits the stream into frames. Yields (index, declared_length, body, error)."""
    o, n = 0, 0
    while o + 4 <= len(stream):
        ln = struct.unpack_from('<I', stream, o)[0]
        o += 4
        n += 1
        if ln == 0 or ln > 64 * 1024 * 1024:
            yield n, ln, b'', f'bogus length ({ln})'
            return
        body = stream[o:o + ln]
        o += ln
        if len(body) < ln:
            yield n, ln, body, f'truncated ({len(body)}/{ln} bytes in capture)'
            return
        yield n, ln, body, None


def main():
    ap = argparse.ArgumentParser(
        description='Decrypts the C2 traffic of PureLogs stage 3 from a pcap.')
    ap.add_argument('pcap')
    ap.add_argument('--key', default=KEY_HEX,
                    help=f'AES-128 key in hex (default: {KEY_HEX})')
    ap.add_argument('--key-from-binary', metavar='PE',
                    help='read the key from the binary instead of using the hardcoded value')
    ap.add_argument('--key-offset', type=lambda s: int(s, 0),
                    default=KEY_FILE_OFFSET,
                    help=f'key offset in the binary (default: 0x{KEY_FILE_OFFSET:X})')
    ap.add_argument('--port', type=int, action='append',
                    help='only keep streams involving this port (repeatable)')
    ap.add_argument('--raw', action='store_true',
                    help='show a hexdump of the plaintext instead of deserializing')
    ap.add_argument('--dump-dir', metavar='DIR',
                    help='write each plaintext to DIR/<stream>.frame<N>.bin')
    args = ap.parse_args()

    key = load_key(args)
    linktype, packets = read_pcap(args.pcap)

    flows = defaultdict(Stream)
    for frame in packets:
        parsed = parse_ip_tcp(strip_link(frame, linktype))
        if not parsed:
            continue
        src, sport, dst, dport, seq, flags, payload = parsed
        if args.port and sport not in args.port and dport not in args.port:
            continue
        flows[(src, sport, dst, dport)].add(seq, flags, payload)

    print(f'{args.pcap}: {len(packets)} packets, linktype {linktype}, {len(flows)} TCP streams')
    print(f'key: {key.hex().upper()}' + (f'  (read from {args.key_from_binary} @ 0x{args.key_offset:X})' if args.key_from_binary else ''))

    active_keys = [key]
    for _, stream_obj in flows.items():
        stream, _ = stream_obj.assemble()
        for _, _, body, err in iter_frames(stream):
            if err or len(body) < 32:
                continue
            for k in list(active_keys):
                pt, cerr = decrypt_frame(body, k)
                if cerr:
                    continue
                sk = extract_session_key(pt)
                if sk and sk not in active_keys:
                    active_keys.append(sk)
                    print(f'  => session key extracted from handshake: {sk.hex().upper()}  (AES-{len(sk)*8})')
                break

    total, ok_count = 0, 0
    for (src, sport, dst, dport), stream_obj in sorted(flows.items()):
        stream, holes = stream_obj.assemble()
        if not stream:
            continue
        label = f'{src}:{sport} -> {dst}:{dport}'
        print(f'\n{"=" * 72}\n{label}   {len(stream)} bytes reassembled')
        if holes:
            print(f'  /!\\ {len(holes)} hole(s) in stream: ' + ', '.join(f'offset {o} ({n} bytes)' for o, n in holes) + '  -> decryption likely corrupted')
        print('=' * 72)

        for n, ln, body, err in iter_frames(stream):
            total += 1
            print(f'\n--- frame {n}: declared length {ln} ---')
            if err:
                print(f'    [{err}]')
                continue
            pt, used_key, cerr = try_decrypt(body, active_keys)
            if pt is None:
                print(f'    [{cerr}]')
                continue
            ok_count += 1
            print(f'    IV    : {body[:16].hex()}')
            print(f'    plain : {len(pt)} bytes' + (f'  [static key]' if used_key is key else f'  [session key AES-{len(used_key)*8}]'))

            if args.dump_dir:
                import os
                os.makedirs(args.dump_dir, exist_ok=True)
                safe = label.replace(':', '_').replace(' -> ', '__')
                path = os.path.join(args.dump_dir, f'{safe}.frame{n}.bin')
                open(path, 'wb').write(pt)
                print(f'    wrote: {path}')

            if args.raw:
                for i in range(0, len(pt), 16):
                    chunk = pt[i:i + 16]
                    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
                    print(f'    {i:08x}  {chunk.hex(" "):<47}  |{printable}|')
            else:
                out = []
                deserialize(pt, 0, 1, out)
                print('\n'.join(out))

    print(f'\n{"=" * 72}')
    print(f'{ok_count}/{total} frame(s) decrypted with valid PKCS7 padding')
    return 0 if ok_count else 1


if __name__ == '__main__':
    sys.exit(main())
