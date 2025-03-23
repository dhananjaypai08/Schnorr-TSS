# Schnorr Based TSS signature aggregation 
- This idea allows users to sign a transaction using multiple private keys using Schnorr Based method which is derived from `ECDSA` and `secp256k1` curve

## Installation 
- Active Virtual environment 
```bash
python3 -m venv env 
source env/bin/activate
```
- Install Dependencies
```bash
pip install -r requirements.txt
```
- Copy and configure `.env` file
```bash
cp env.example .env
# Add your private keys
```
- Run the script 
```bash
python3 main.py
```