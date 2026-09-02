"""Minimal read-only TFTP server (RFC 1350 + blksize/tsize options).

Exists because the MS510TXUP's HTTP upload CGI transfers an image the switch
will not boot, and TFTP is a completely different code path in that firmware.
Read-only on purpose: it serves one directory and refuses writes.
"""
import os
import socket
import struct
import sys
import threading
import time

OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR, OP_OACK = 1, 2, 3, 4, 5, 6


def serve(directory, port=69, quiet=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    if not quiet:
        print("  tftp serving %s on udp/%d" % (directory, port), flush=True)

    while True:
        data, addr = sock.recvfrom(65535)
        if len(data) < 2:
            continue
        opcode = struct.unpack("!H", data[:2])[0]
        if opcode != OP_RRQ:
            sock.sendto(struct.pack("!HH", OP_ERROR, 4) + b"only reads\0", addr)
            continue
        parts = data[2:].split(b"\0")
        filename = parts[0].decode("latin-1")
        opts = {}
        rest = [p for p in parts[2:] if p]
        for i in range(0, len(rest) - 1, 2):
            opts[rest[i].decode("latin-1").lower()] = rest[i + 1].decode("latin-1")
        threading.Thread(target=_send, args=(directory, filename, addr, opts, quiet),
                         daemon=True).start()


def _send(directory, filename, addr, opts, quiet):
    # Serve by basename only - the client may prefix a path like "./".
    path = os.path.join(directory, os.path.basename(filename))
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn.settimeout(8)
    if not os.path.isfile(path):
        conn.sendto(struct.pack("!HH", OP_ERROR, 1) + b"not found\0", addr)
        if not quiet:
            print("  RRQ %s -> NOT FOUND" % filename, flush=True)
        return

    size = os.path.getsize(path)
    blksize = 512
    ack = {}
    if "blksize" in opts:
        blksize = max(8, min(int(opts["blksize"]), 8192))
        ack["blksize"] = str(blksize)
    if "tsize" in opts:
        ack["tsize"] = str(size)
    if not quiet:
        print("  RRQ %s (%d bytes) from %s blksize=%d" % (filename, size, addr[0], blksize), flush=True)

    if ack:
        # Acknowledge negotiated options, then wait for the client's ACK 0.
        payload = b"".join(k.encode() + b"\0" + v.encode() + b"\0" for k, v in ack.items())
        for _ in range(5):
            conn.sendto(struct.pack("!H", OP_OACK) + payload, addr)
            try:
                reply, addr2 = conn.recvfrom(1024)
            except socket.timeout:
                continue
            if struct.unpack("!H", reply[:2])[0] == OP_ACK:
                addr = addr2
                break
        else:
            if not quiet:
                print("  no ACK for OACK - giving up", flush=True)
            return

    sent = 0
    with open(path, "rb") as fh:
        block = 1
        while True:
            chunk = fh.read(blksize)
            pkt = struct.pack("!HH", OP_DATA, block & 0xFFFF) + chunk
            for _ in range(6):
                conn.sendto(pkt, addr)
                try:
                    reply, addr = conn.recvfrom(1024)
                except socket.timeout:
                    continue
                op, blk = struct.unpack("!HH", reply[:4])
                if op == OP_ACK and blk == (block & 0xFFFF):
                    break
                if op == OP_ERROR:
                    if not quiet:
                        print("  client error: %s" % reply[4:].decode("latin-1", "replace")[:80], flush=True)
                    return
            else:
                if not quiet:
                    print("  timed out on block %d" % block, flush=True)
                return
            sent += len(chunk)
            if not quiet and block % 2000 == 0:
                print("   sent %d/%d bytes" % (sent, size), flush=True)
            block += 1
            if len(chunk) < blksize:
                break
    if not quiet:
        print("  transfer complete: %d bytes" % sent, flush=True)


if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 69
    serve(d, p)
