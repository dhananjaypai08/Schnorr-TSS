from ecdsa import SigningKey, SECP256k1
from dotenv import load_dotenv
import os
from ecdsa.ellipticcurve import Point

load_dotenv()

private_keys_hex = [
    os.getenv("PRIVATE_KEY_1"),
    os.getenv("PRIVATE_KEY_2"),
    os.getenv("PRIVATE_KEY_3"),
]
curve = SECP256k1.curve

def generate_nonce():
    return SigningKey.generate(curve=SECP256k1)

num_signers = 3
private_keys = [SigningKey.from_string(bytes.fromhex(key[2:]), curve=SECP256k1) for key in private_keys_hex]
nonces = [generate_nonce() for _ in range(len(private_keys))]
public_nonces = [nonce.verifying_key for nonce in nonces]

aggregated_nonce_point = public_nonces[0].pubkey.point
for nonce in public_nonces[1:]:
    aggregated_nonce_point = aggregated_nonce_point + nonce.pubkey.point

aggregated_nonce = public_nonces[0].from_public_point(aggregated_nonce_point, SECP256k1)
print(aggregated_nonce)
