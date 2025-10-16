# simplehash/base64codec.py
# Implementasi manual Base64 berbasis objek, tanpa modul base64

class Base64:
    _alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    _rev_table = {c: i for i, c in enumerate(_alphabet)}

    def encode(self, data: bytes) -> str:
        """Encode bytes menjadi string Base64."""
        encoded = []
        for i in range(0, len(data), 3):
            triple = data[i:i+3]
            padding = 3 - len(triple)
            triple += b'\x00' * padding

            # Ubah 3 byte menjadi 4 grup 6-bit
            n = (triple[0] << 16) | (triple[1] << 8) | triple[2]
            for j in range(18, -1, -6):
                encoded.append(chr(self._alphabet[(n >> j) & 0x3F]))

            if padding:
                encoded[-padding:] = "=" * padding  # tambahkan '=' padding

        return ''.join(encoded)

    def decode(self, data: str) -> bytes:
        """Decode string Base64 menjadi bytes."""
        clean_data = data.strip().replace("\n", "").replace("\r", "")
        padding = clean_data.count("=")
        clean_data = clean_data.rstrip("=")

        bits = 0
        bit_length = 0
        output = bytearray()

        for c in clean_data.encode():
            if c not in self._rev_table:
                raise ValueError(f"Karakter tidak valid dalam Base64: {chr(c)}")
            bits = (bits << 6) | self._rev_table[c]
            bit_length += 6
            if bit_length >= 8:
                bit_length -= 8
                output.append((bits >> bit_length) & 0xFF)

        if padding:
            output = output[:-padding]

        return bytes(output)
