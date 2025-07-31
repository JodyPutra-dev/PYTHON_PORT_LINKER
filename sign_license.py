# sign_license.py
import rsa

# Load your private key (never include this with the app!)
with open("private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

# Use email or name
user_data = "jody@example.com"
signature = rsa.sign(user_data.encode(), private_key, "SHA-256")

with open("license.lic", "wb") as f:
    f.write(user_data.encode() + b"\n" + signature)
