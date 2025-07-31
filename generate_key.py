import rsa

# Generate a new 2048-bit RSA key pair
public_key, private_key = rsa.newkeys(2048)

# Save the public key (to be included in your app)
with open("public.pem", "wb") as f:
    f.write(public_key.save_pkcs1("PEM"))

# Save the private key (keep this secret, never share)
with open("private.pem", "wb") as f:
    f.write(private_key.save_pkcs1("PEM"))

print("RSA key pair generated successfully.")
print("✔ public.pem → use in your app for verification")
print("✔ private.pem → keep safe, use to sign license keys")
