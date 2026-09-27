"""Command-line interface for the simple ChaCha20 message tool."""

import secrets

from chacha20 import decrypt, encrypt


def encrypt_message():
    message = input("Message to encrypt: ").encode("utf-8")
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(8)
    ciphertext = encrypt(message, key, nonce)

    print("\nEncrypted message:", ciphertext.hex())
    print("Key:", key.hex())
    print("Nonce:", nonce.hex())
    print("\nKeep the key and nonce. They are needed to decrypt the message.")


def decrypt_message():
    try:
        ciphertext = bytes.fromhex(input("Encrypted message (hex): "))
        key = bytes.fromhex(input("Key (hex): "))
        nonce = bytes.fromhex(input("Nonce (hex): "))
        message = decrypt(ciphertext, key, nonce).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        print("Could not decrypt message:", error)
        return

    print("\nDecrypted message:", message)


def main():
    print("ChaCha20 message tool")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    choice = input("Choose an option: ").strip()

    if choice == "1":
        encrypt_message()
    elif choice == "2":
        decrypt_message()
    else:
        print("Please choose 1 or 2.")


if __name__ == "__main__":
    main()
