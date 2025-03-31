import hashlib
import random
import coincurve
from fastecdsa.keys import gen_keypair
from ecdsa.util import sigencode_der, sigdecode_der
from hashlib import sha256
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from dotenv import load_dotenv
from eth_keys import keys
import os

load_dotenv()

hex_private_keys = [
    os.getenv("PRIVATE_KEY_1"),
    os.getenv("PRIVATE_KEY_2"),
    os.getenv("PRIVATE_KEY_3")
]
private_keys = [int(pk, 16) for pk in hex_private_keys]
def get_public_key(private_key):
    """Computes the public key from a given private key."""
    G = secp256k1.G 
    return private_key * G 
public_keys = [get_public_key(pk) for pk in private_keys]

print("Private Keys:", private_keys)
print("Public Keys:", *public_keys)

def aggregate_public_keys(public_keys):
    """Aggregate public keys using elliptic curve addition."""
    agg_pub_key = None

    for pub_key in public_keys:
        if agg_pub_key is None:
            agg_pub_key = pub_key
        else:
            agg_pub_key += pub_key
    
    return agg_pub_key

agg_pub_key = aggregate_public_keys(public_keys)
print("Aggregated Public Key:", agg_pub_key)

def point_to_bytes(point):
    """Encodes an elliptic curve point into bytes."""
    return point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")

def schnorr_sign(message, private_keys):
    """Schnorr multi-signature process."""
    msg_hash = sha256(message.encode()).digest()

    nonces = [gen_keypair(secp256k1)[0] for _ in private_keys]

    R_points = [r * secp256k1.G for r in nonces]

    R_agg = aggregate_public_keys(R_points)

    challenge_data = point_to_bytes(R_agg) + point_to_bytes(agg_pub_key) + msg_hash
    e = int.from_bytes(sha256(challenge_data).digest(), "big") % secp256k1.q

    # Compute individual signatures: s_i = r_i + e * x_i
    signatures = [(nonces[i] + e * private_keys[i]) % secp256k1.q for i in range(len(private_keys))]

    # Aggregate signatures: s_agg = sum(s_i)
    s_agg = sum(signatures) % secp256k1.q

    return R_agg, s_agg

message = "Hello Schnorr!"
R_agg, s_agg = schnorr_sign(message, private_keys)

def schnorr_verify(message, R_agg, s_agg, agg_pub_key):
    """Verify Schnorr multi-signature."""
    msg_hash = sha256(message.encode()).digest()

    challenge_data = point_to_bytes(R_agg) + point_to_bytes(agg_pub_key) + msg_hash
    e = int.from_bytes(sha256(challenge_data).digest(), "big") % secp256k1.q

    # Check if s_agg * G == R_agg + e * agg_pub_key
    left = s_agg * secp256k1.G
    right = R_agg + e * agg_pub_key

    return left == right

print("Signature Valid:", schnorr_verify(message, R_agg, s_agg, agg_pub_key))