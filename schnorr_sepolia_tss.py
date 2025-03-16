from dotenv import load_dotenv
import os
import json
import ecdsa
import ecdsa.util
from hashlib import sha256
from web3 import Web3
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict, encode_transaction


load_dotenv()


WEB3_PROVIDER = "https://eth-sepolia.public.blastapi.io"
w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))


private_keys_hex = [
    os.getenv("PRIVATE_KEY_1"),
    os.getenv("PRIVATE_KEY_2"),
    os.getenv("PRIVATE_KEY_3"),
]
private_keys = [ecdsa.SigningKey.from_string(bytes.fromhex(key[2:]), curve=ecdsa.SECP256k1) for key in private_keys_hex]


def deterministic_nonce(private_key, message):
    hashed_input = sha256(private_key.to_string() + message).digest()
    return ecdsa.SigningKey.from_string(hashed_input[:32], curve=ecdsa.SECP256k1)

message = b"Schnorr TSS Transaction"
hashed_message = sha256(message).digest()
nonces = [deterministic_nonce(pk, hashed_message) for pk in private_keys]

public_nonces = [nonce.verifying_key.pubkey.point for nonce in nonces]

aggregated_nonce_point = public_nonces[0]
for nonce in public_nonces[1:]:
    aggregated_nonce_point += nonce

aggregated_nonce = private_keys[0].verifying_key.from_public_point(aggregated_nonce_point, ecdsa.SECP256k1)

print(f"🔹 Aggregated Nonce (R): {aggregated_nonce_point}")

from_address = w3.eth.account.from_key(private_keys_hex[0]).address
nonce = w3.eth.get_transaction_count(from_address)

transaction = {
    "nonce": nonce,
    "to": "0x4331BE0C025C9C73ea0C5BCa45539AdEab8fe73B", 
    "value": w3.to_wei(0.001, "ether"),
    "gas": 21000,
    "gasPrice": w3.to_wei(10, "gwei"),
    "chainId": 11155111,
}


unsigned_tx = serializable_unsigned_transaction_from_dict(transaction)
tx_hash = sha256(unsigned_tx.hash()).digest()

print(f"📌 Transaction Hash: {tx_hash.hex()}")

def sign_partial(private_key, nonce, aggregated_nonce, message):
    challenge = int.from_bytes(sha256(aggregated_nonce.to_string() + private_key.verifying_key.to_string() + message).digest(), 'big')
    s_i = (int.from_bytes(nonce.to_string(), 'big') + challenge * int.from_bytes(private_key.to_string(), 'big')) % private_key.curve.order
    return s_i

partial_signatures = [
    sign_partial(private_keys[i], nonces[i], aggregated_nonce, tx_hash)
    for i in range(len(private_keys))
]


aggregated_s = sum(partial_signatures) % private_keys[0].curve.order


print(f"✅ Aggregated Schnorr Signature: R = {aggregated_nonce_point}, s = {aggregated_s}")
r = int(aggregated_nonce_point.x())
s = aggregated_s
v = 27  # Schnorr does not have a recovery ID, so we use a fixed value

aggregated_signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

print(f"📌 Aggregated Signature (r, s): {aggregated_signature.hex()}")

# ✅ Properly encode the transaction before sending
signed_tx = encode_transaction(unsigned_tx, (v, r, s))

tx_hash = w3.eth.send_raw_transaction(signed_tx)

print(f"🚀 Transaction Sent! Tx Hash: {tx_hash.hex()}")
