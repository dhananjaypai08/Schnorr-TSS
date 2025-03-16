from dotenv import load_dotenv
import os 
from ecdsa import SigningKey, SECP256k1
import ecdsa.util
from hashlib import sha256

load_dotenv()

private_keys_hex = [
    os.getenv("PRIVATE_KEY_1"),
    os.getenv("PRIVATE_KEY_2"),
    os.getenv("PRIVATE_KEY_3"),
]

private_keys = [SigningKey.from_string(bytes.fromhex(key[2:]), curve=SECP256k1) for key in private_keys_hex]
num_signers = len(private_keys)

message = b"Message from dj"
hashed_message = sha256(message).digest()
print("hashed message", hashed_message)

def sign_partial(private_key, nonce, message):
    return private_key.sign_digest(hashed_message, sigencode=ecdsa.util.sigencode_string)

def generate_nonce():
    return SigningKey.generate(curve=SECP256k1)

nonces = [generate_nonce() for _ in range(len(private_keys))]

partial_signatures = [sign_partial(private_keys[i], nonces[i], hashed_message) for i in range(len(private_keys))]

r, s_values = zip(*[ecdsa.util.sigdecode_string(sig, private_keys[0].privkey.order) for sig in partial_signatures])
print(r)

curve_order = private_keys[0].privkey.order
aggregated_s = sum(s_values) % curve_order

aggregated_signature = ecdsa.util.sigencode_string(r[0], aggregated_s, curve_order)
print(aggregated_signature)