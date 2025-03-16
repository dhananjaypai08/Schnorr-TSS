import os 
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.ellipticcurve import Point
from hashlib import sha256
from dotenv import load_dotenv

load_dotenv()

private_keys_hex = [
    os.getenv("PRIVATE_KEY_1"),
    os.getenv("PRIVATE_KEY_2"),
    os.getenv("PRIVATE_KEY_3"),
]

curve = SECP256k1.curve

private_keys = [SigningKey.from_string(bytes.fromhex(key[2:]), curve=SECP256k1) for key in private_keys_hex]

public_keys = [pk.verifying_key for pk in private_keys]

aggregated_pubkey_point = public_keys[0].pubkey.point

for pk in public_keys[1:]:
    aggregated_pubkey_point = aggregated_pubkey_point + pk.pubkey.point

aggregated_pubkey = public_keys[0].from_public_point(aggregated_pubkey_point, SECP256k1)
print(aggregated_pubkey)