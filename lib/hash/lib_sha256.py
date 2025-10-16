# simplehash/sha256.py
# Implementasi SHA-256 berbasis objek tanpa hashlib / struct

class SHA256:
    _K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    def __init__(self):
        self._h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        self._buffer = b""
        self._counter = 0

    def flush(self):
        """Reset state internal agar bisa digunakan ulang untuk hash baru."""
        self._h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        self._buffer = b""
        self._counter = 0

    @staticmethod
    def _right_rotate(x, n):
        return ((x >> n) | (x << (32 - n))) & 0xffffffff

    def update(self, data: bytes):
        """Tambahkan data ke hash (streaming)."""
        self._buffer += data
        self._counter += len(data)
        while len(self._buffer) >= 64:
            self._process_chunk(self._buffer[:64])
            self._buffer = self._buffer[64:]

    def _process_chunk(self, chunk: bytes):
        W = [int.from_bytes(chunk[i:i+4], 'big') for i in range(0, 64, 4)] + [0]*48
        for t in range(16, 64):
            s0 = self._right_rotate(W[t-15], 7) ^ self._right_rotate(W[t-15], 18) ^ (W[t-15] >> 3)
            s1 = self._right_rotate(W[t-2], 17) ^ self._right_rotate(W[t-2], 19) ^ (W[t-2] >> 10)
            W[t] = (W[t-16] + s0 + W[t-7] + s1) & 0xffffffff

        a, b, c, d, e, f, g, h = self._h

        for t in range(64):
            S1 = self._right_rotate(e, 6) ^ self._right_rotate(e, 11) ^ self._right_rotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + self._K[t] + W[t]) & 0xffffffff
            S0 = self._right_rotate(a, 2) ^ self._right_rotate(a, 13) ^ self._right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff

            h, g, f, e, d, c, b, a = (
                g, f, e, (d + temp1) & 0xffffffff,
                c, b, a, (temp1 + temp2) & 0xffffffff
            )

        self._h = [(x + y) & 0xffffffff for x, y in zip(self._h, [a,b,c,d,e,f,g,h])]

    def digest(self) -> bytes:
        """Keluarkan hasil hash dalam bentuk bytes."""
        total_bits = self._counter * 8
        data = self._buffer + b'\x80'
        while (len(data) * 8) % 512 != 448:
            data += b'\x00'
        data += total_bits.to_bytes(8, 'big')

        for i in range(0, len(data), 64):
            self._process_chunk(data[i:i+64])

        return b''.join(x.to_bytes(4, 'big') for x in self._h)

    def hexdigest(self) -> str:
        return self.digest().hex()
