"""
PiCipher v1
Güvenli metin şifreleme motoru.

- AES-256-GCM ile şifreleme
- Scrypt ile parola -> anahtar dönüşümü
- Rastgele salt ve nonce
- Yanlış anahtarda çözme başarısız olur
- UTF-8 / Türkçe karakter desteği
- PiCipher için π tabanlı katman

Not:
π'nin kendisi gizli değildir. Güvenliği sağlayan ana mekanizma AES-256-GCM
ve Scrypt'tir. π katmanı PiCipher'ın algoritmik özelliğidir.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# PiCipher'ın π dizisi.
# Nokta kaldırılmıştır.
PI_DIGITS = (
    "314159265358979323846264338327950288419716939937510"
    "58209749445923078164062862089986280348253421170679"
    "82148086513282306647093844609550582231725359408128"
)


VERSION = b"PC01"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32


def pi_layer():
    """
    π basamaklarından PiCipher'a özel sabit bir katman üretir.
    """
    pi_bytes = PI_DIGITS.encode("ascii")

    return hashlib.sha256(
        b"PiCipher-PI-LAYER:" + pi_bytes
    ).digest()


PI_LAYER = pi_layer()


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Kullanıcının anahtarını Scrypt kullanarak
    256-bit AES anahtarına dönüştürür.

    Örneğin anahtar '1' olabilir.
    Gerçek kullanımda uzun ve rastgele bir parola önerilir.
    """

    if not isinstance(password, str):
        raise TypeError("Anahtar metin biçiminde olmalıdır.")

    if password == "":
        raise ValueError("Anahtar boş bırakılamaz.")

    # π katmanı KDF girdisine dahil edilir.
    password_bytes = password.encode("utf-8") + PI_LAYER

    key = hashlib.scrypt(
        password_bytes,
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=KEY_SIZE,
    )

    return key


def pi_mix(data: bytes) -> bytes:
    """
    Veriyi π basamaklarıyla reversible şekilde karıştırır.

    Bu katman AES'in yerine geçmez.
    PiCipher'ın π tabanlı tasarım katmanıdır.
    """

    result = bytearray(len(data))

    pi = PI_DIGITS

    for i, value in enumerate(data):
        digit = ord(pi[i % len(pi)]) - 48

        # π basamağı ile reversible dönüşüm
        result[i] = (value + digit) % 256

    return bytes(result)


def pi_unmix(data: bytes) -> bytes:
    """
    pi_mix işleminin tersidir.
    """

    result = bytearray(len(data))

    pi = PI_DIGITS

    for i, value in enumerate(data):
        digit = ord(pi[i % len(pi)]) - 48

        result[i] = (value - digit) % 256

    return bytes(result)


def encrypt(text: str, password: str) -> str:
    """
    Metni AES-256-GCM ile şifreler.

    Dönen değer Base64 biçimindedir.
    """

    if not isinstance(text, str):
        raise TypeError("Şifrelenecek veri metin olmalıdır.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)

    # PiCipher π katmanı
    plaintext = text.encode("utf-8")
    mixed = pi_mix(plaintext)

    # Şifreleme sırasında sürüm + π katmanı doğrulamaya dahil edilir.
    aad = VERSION + PI_LAYER

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        mixed,
        aad,
    )

    # Dosya/mesaj formatı:
    #
    # PC01 | SALT | NONCE | CIPHERTEXT
    #
    packet = VERSION + salt + nonce + ciphertext

    return base64.urlsafe_b64encode(packet).decode("ascii")


def decrypt(ciphertext: str, password: str) -> str:
    """
    PiCipher şifreli metni çözer.

    Anahtar yanlışsa veya veri değiştirilmişse
    hata verir.
    """

    if not isinstance(ciphertext, str):
        raise TypeError("Şifreli veri metin olmalıdır.")

    try:
        packet = base64.urlsafe_b64decode(
            ciphertext.encode("ascii")
        )
    except Exception as exc:
        raise ValueError("Şifreli veri geçersiz.") from exc

    minimum_size = (
        len(VERSION)
        + SALT_SIZE
        + NONCE_SIZE
        + 16
    )

    if len(packet) < minimum_size:
        raise ValueError("Şifreli veri çok kısa veya bozuk.")

    version = packet[:4]

    if version != VERSION:
        raise ValueError("Desteklenmeyen PiCipher sürümü.")

    position = len(VERSION)

    salt = packet[
        position:position + SALT_SIZE
    ]

    position += SALT_SIZE

    nonce = packet[
        position:position + NONCE_SIZE
    ]

    position += NONCE_SIZE

    encrypted_data = packet[position:]

    key = derive_key(password, salt)

    aad = VERSION + PI_LAYER

    aes = AESGCM(key)

    try:
        mixed = aes.decrypt(
            nonce,
            encrypted_data,
            aad,
        )
    except Exception as exc:
        raise ValueError(
            "Anahtar yanlış veya şifreli veri değiştirilmiş."
        ) from exc

    try:
        plaintext = pi_unmix(mixed)

        return plaintext.decode("utf-8")

    except UnicodeDecodeError as exc:
        raise ValueError(
            "Metin çözülemedi."
        ) from exc


def test():
    """
    Temel otomatik test.
    """

    mesaj = "Merhaba PiCipher! Türkçe karakterler: ç ğ ı ö ş ü"

    anahtar = "1"

    sifreli = encrypt(
        mesaj,
        anahtar,
    )

    cozulmus = decrypt(
        sifreli,
        anahtar,
    )

    assert cozulmus == mesaj

    # Yanlış anahtarın çalışmaması gerekir.
    try:
        decrypt(
            sifreli,
            "2",
        )

        raise AssertionError(
            "Yanlış anahtar kabul edildi!"
        )

    except ValueError:
        pass

    print("PiCipher testi başarılı.")
    print()
    print("Orijinal:")
    print(mesaj)
    print()
    print("Şifreli:")
    print(sifreli)
    print()
    print("Çözülmüş:")
    print(cozulmus)


if __name__ == "__main__":
    test()
