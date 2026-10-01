import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


VERSION = b"PC01"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

PI_DIGITS = (
    "314159265358979323846264338327950288419716939937510"
    "58209749445923078164062862089986280348253421170679"
)


def derive_key(password, salt):
    if not password:
        raise ValueError("Anahtar boş bırakılamaz.")

    password_bytes = password.encode("utf-8")

    return hashlib.scrypt(
        password_bytes,
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=KEY_SIZE,
    )


def pi_mix(data):
    result = bytearray()

    for i, value in enumerate(data):
        digit = int(PI_DIGITS[i % len(PI_DIGITS)])
        result.append((value + digit) % 256)

    return bytes(result)


def pi_unmix(data):
    result = bytearray()

    for i, value in enumerate(data):
        digit = int(PI_DIGITS[i % len(PI_DIGITS)])
        result.append((value - digit) % 256)

    return bytes(result)


def encrypt(text, password):
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)

    data = text.encode("utf-8")
    data = pi_mix(data)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        data,
        VERSION,
    )

    packet = VERSION + salt + nonce + ciphertext

    return base64.urlsafe_b64encode(packet).decode("ascii")


def decrypt(ciphertext, password):
    try:
        packet = base64.urlsafe_b64decode(
            ciphertext.encode("ascii")
        )
    except Exception:
        raise ValueError("Şifreli veri geçersiz.")

    if not packet.startswith(VERSION):
        raise ValueError("Geçersiz PiCipher verisi.")

    position = len(VERSION)

    salt = packet[
        position:position + SALT_SIZE
    ]

    position += SALT_SIZE

    nonce = packet[
        position:position + NONCE_SIZE
    ]

    position += NONCE_SIZE

    encrypted = packet[position:]

    key = derive_key(password, salt)

    aes = AESGCM(key)

    try:
        data = aes.decrypt(
            nonce,
            encrypted,
            VERSION,
        )
    except Exception:
        raise ValueError(
            "Anahtar yanlış veya veri değiştirilmiş."
        )

    data = pi_unmix(data)

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Metin çözülemedi.")


if __name__ == "__main__":
    mesaj = "Merhaba PiCipher! Şifreleme testi."
    anahtar = "1"

    sifreli = encrypt(mesaj, anahtar)

    print("Şifreli:")
    print(sifreli)

    print()
    print("Çözülmüş:")
    print(decrypt(sifreli, anahtar))
