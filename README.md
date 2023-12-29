# signpy
Sign messages with ease

## Quickstart
```py
import signpy

key = signpy.generate()  # generates a secret key

signer = signpy.SigningKey(key)
signature = signer.sign(b"Hello, world!")

public_key = signer.public_key
verifier = signpy.VerifyingKey(public_key)

verifier.verify(b"Hello, world!", signature)  # True
verifier.verify(b"Goodbye, world!", signature)  # False

verifier = signer.verifier

verifier.verify(b"Hello, world!", signature)  # True
```
