"""Small QEMU RFB client for isolated tests (raw frames, US scancodes, no auth)."""
import socket
import struct
import time
import zlib

KEYS = dict(enter=0xFF0D, tab=0xFF09, escape=0xFF1B, ctrl=0xFFE3,
            alt=0xFFE9, shift=0xFFE1, f1=0xFFBE, f2=0xFFBF, f3=0xFFC0, f6=0xFFC3)
SHIFTED = dict(zip('~!@#$%^&*()_+{}|:"<>?', '`1234567890-=[]\\;\',./'))
SCAN = dict(zip('1234567890', range(0x02, 0x0c)))
SCAN.update(zip('qwertyuiop', range(0x10, 0x1a)))
SCAN.update(zip('asdfghjkl', range(0x1e, 0x27)))
SCAN.update(zip('zxcvbnm', range(0x2c, 0x33)))
SCAN.update({'-': 0x0c, '=': 0x0d, '[': 0x1a, ']': 0x1b, ';': 0x27,
             "'": 0x28, '`': 0x29, '\\': 0x2b, ',': 0x33, '.': 0x34,
             '/': 0x35, ' ': 0x39})
SPECIAL_SCAN = dict(zip(KEYS.values(), [0x1c, 0x0f, 0x01, 0x1d, 0x38, 0x2a, 0x3b, 0x3c, 0x3d, 0x40]))


class Console:
    def __init__(self, port):
        self.socket = socket.create_connection(('127.0.0.1', port), timeout=10)
        self.read(12)
        self.socket.sendall(b'RFB 003.008\n')
        types = self.read(self.read(1)[0])
        if 1 not in types:
            raise ValueError('Test console must use no-auth loopback VNC')
        self.socket.sendall(b'\x01')
        assert self.read(4) == b'\0' * 4
        self.socket.sendall(b'\x01')
        self.width, self.height = struct.unpack('!HH', self.read(4))
        self.read(16)
        name_length = struct.unpack('!I', self.read(4))[0]
        assert name_length < 4096 and self.width * self.height < 4000000
        self.read(name_length)
        self.socket.sendall(b'\0\0\0\0' + struct.pack('!BBBBHHHBBB3x', 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))
        self.socket.sendall(struct.pack('!BBHi', 2, 0, 1, 0))

    def read(self, size):
        data = b''
        while len(data) < size:
            chunk = self.socket.recv(size - len(data))
            if not chunk:
                raise EOFError('VNC console closed')
            data += chunk
        return data

    def event(self, key, down):
        code = SPECIAL_SCAN.get(key)
        if code is None:
            code = SCAN[chr(key)]
        # QEMU extended key events with an unspecified keysym avoid its
        # Caps Lock synchronization. The guest receives explicit US scancodes.
        self.socket.sendall(struct.pack('!BBHII', 255, 0, int(down), 0, code))
        time.sleep(0.015)

    def key(self, name):
        key = KEYS.get(name, ord(name) if len(name) == 1 else None)
        if key is None:
            raise ValueError(name)
        self.event(key, True)
        self.event(key, False)

    def chord(self, *names):
        for name in names:
            self.event(KEYS[name], True)
        for name in reversed(names):
            self.event(KEYS[name], False)

    def type(self, text):
        for character in text:
            if character == '\n':
                self.key('enter')
            else:
                shifted = character.isupper() or character in '~!@#$%^&*()_+{}|:"<>?'
                if shifted:
                    self.event(KEYS['shift'], True)
                # Send the physical unshifted US key while holding Shift.
                self.key(character.lower() if character.isupper() else SHIFTED.get(character, character))
                if shifted:
                    self.event(KEYS['shift'], False)

            time.sleep(0.01)  # Keep guest console input queues from dropping keys.

    def screenshot(self, path):
        w, h = self.width, self.height
        self.socket.sendall(struct.pack('!BBHHHH', 3, 0, 0, 0, w, h))
        while True:
            kind = self.read(1)[0]
            if kind == 0:
                break
            if kind == 2:  # bell
                continue
            if kind == 3:  # clipboard
                self.read(3)
                size = struct.unpack('!I', self.read(4))[0]
                assert size < 1000000
                self.read(size)
                continue
            raise ValueError(f'Unexpected RFB message {kind}')
        _, count = struct.unpack('!BH', self.read(3))
        frame = bytearray(w * h * 3)
        for _ in range(count):
            x, y, rw, rh, encoding = struct.unpack('!HHHHi', self.read(12))
            assert encoding == 0 and x + rw <= w and y + rh <= h
            pixels = self.read(rw * rh * 4)
            for row in range(rh):
                start = row * rw * 4
                rgb = bytearray(rw * 3)
                for col in range(rw):
                    rgb[col * 3:col * 3 + 3] = pixels[start + col * 4:start + col * 4 + 3][::-1]
                dst = ((y + row) * w + x) * 3
                frame[dst:dst + rw * 3] = rgb
        def chunk(kind, data):
            return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data) & 0xFFFFFFFF)
        raw = b''.join(b'\0' + frame[y * w * 3:(y + 1) * w * 3] for y in range(h))
        path.write_bytes(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!IIBBBBB', w, h, 8, 2, 0, 0, 0)) +
                         chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))

    def close(self):
        self.socket.close()
