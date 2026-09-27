# ChaCha20 message tool

A small Python program that encrypts and decrypts text with ChaCha20. It is
split into a cipher module and a command-line interface so each part has one
clear job.

## Run it

```text
python3 main.py
```

Choose `1` to encrypt a message. The program prints the ciphertext, key, and
nonce as hexadecimal values. Save all three values. Choose `2` and enter them
to decrypt the message.

## Test it

```text
python3 -m unittest -v
```

## Notes

- The key is 32 bytes and the nonce is 8 bytes, matching the supplied
  `references/chacha20.py` implementation and its test vectors.
- ChaCha20 is a stream cipher, so encryption and decryption use the same XOR
  operation.
- This is an educational ChaCha20 implementation. It does not add
  authentication with Poly1305, so it cannot detect a changed ciphertext.
