import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip

# Streamlit Title
st.title("Encryption/Decryption App")

# Sidebar with Algorithm Information
st.sidebar.title("Algorithm Information")

algorithm_info = {
    "RSA": """
        **RSA (Rivest-Shamir-Adleman) Encryption**
        
        **History**: Developed in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman.
        
        **Mathematical Foundation**:
        1. Choose two large prime numbers: p and q.
        2. Compute n = p × q (modulus).
        3. Compute Euler’s totient function: φ(n) = (p - 1)(q - 1).
        4. Select an encryption exponent e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1.
        5. Compute the private key d such that d ≡ e^(-1) (mod φ(n)).
        6. Public key: (e, n); Private key: (d, n).
        7. Encryption: Ciphertext C = M^e mod n.
        8. Decryption: Plaintext M = C^d mod n.
        
        **Applications**:
        - Secure web communication (TLS/SSL)
        - Digital signatures for authentication
        - Email encryption (PGP)
        
        **Pros**:
        - High security for large key sizes
        - Widely used and trusted
        
        **Cons**:
        - Slow for large data encryption
        - Large key sizes needed for strong security
        - Susceptible to quantum computing attacks in the future
    """,
    "ECC": """
        **Elliptic Curve Cryptography (ECC)**
        
        **History**: Introduced in 1985 by Neal Koblitz and Victor Miller as an alternative to RSA.
        
        **Mathematical Foundation**:
        - Based on the equation: y² ≡ x³ + ax + b (mod p).
        - Utilizes properties of elliptic curves over finite fields.
        - Key generation uses elliptic curve point multiplication: Q = d × P.
        - Encryption often uses Elliptic Curve Diffie-Hellman (ECDH) for secure key exchange.
        
        **Applications**:
        - Mobile and IoT device security
        - Bitcoin and blockchain transaction signatures
        - Secure messaging protocols like Signal and WhatsApp
        
        **Pros**:
        - Strong security with smaller key sizes compared to RSA (256-bit ECC is roughly equivalent to 3072-bit RSA)
        - Efficient for mobile and low-power devices
        - More resistant to quantum attacks than RSA
        
        **Cons**:
        - More complex implementation
        - Limited support in legacy systems
        - Requires careful parameter selection to avoid vulnerabilities (e.g., weak curves)
    """,
    "AES": """
        **Advanced Encryption Standard (AES)**
        
        **History**: Developed by Belgian cryptographers Vincent Rijmen and Joan Daemen in 2001 as a successor to DES.
        
        **Mathematical Foundation**:
        - Operates on fixed-size blocks of data (128 bits).
        - Uses a substitution-permutation network (SPN) with multiple rounds (10, 12, or 14 rounds depending on key size).
        - Key sizes: 128-bit, 192-bit, and 256-bit.
        - Each round consists of substitution, permutation, and key addition steps.
        
        **Modes of Operation**:
        - ECB (Electronic Codebook) - Not recommended due to patterns in ciphertext.
        - CBC (Cipher Block Chaining) - More secure but requires an initialization vector (IV).
        - GCM (Galois/Counter Mode) - Provides both encryption and authentication.
        
        **Applications**:
        - Secure file encryption
        - TLS/SSL encryption
        - Encrypted disk storage (BitLocker, FileVault)
        
        **Pros**:
        - Fast and efficient for data encryption
        - Widely adopted for secure communication
        - Strong security with proper implementation
        
        **Cons**:
        - Requires secure key management
        - Limited by block size (128 bits, requiring padding for smaller inputs)
        - Vulnerable to side-channel attacks if improperly implemented
    """,
    "Blowfish": """
        **Blowfish Cipher**
        
        **History**: Designed in 1993 by Bruce Schneier as a fast and secure alternative to DES.
        
        **Mathematical Foundation**:
        - Operates on a 16-round Feistel network.
        - Uses a block size of 64 bits (less secure against modern attacks).
        - Key expansion generates 18 subkeys and four S-boxes using the original key.
        - Each encryption round involves permutation and key-dependent substitutions.
        
        **Applications**:
        - Password hashing (bcrypt)
        - Older VPN implementations
        - Legacy software encryption
        
        **Pros**:
        - Fast encryption with a flexible key length (32–448 bits)
        - Good performance on low-power devices
        - Free and unpatented
        
        **Cons**:
        - Outdated for modern security needs (small 64-bit block size makes it vulnerable to birthday attacks)
        - Considered less secure than AES for long-term use
        - Not recommended for new applications due to better alternatives
    """


}

for algo, description in algorithm_info.items():
    with st.sidebar.expander(algo):
        st.markdown(description)

# Persist keys across sessions
if "rsa_private_key" not in st.session_state:
    st.session_state.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    st.session_state.rsa_public_key = st.session_state.rsa_private_key.public_key()

if "ecc_private_key" not in st.session_state:
    st.session_state.ecc_private_key = ec.generate_private_key(ec.SECP256R1())
    st.session_state.ecc_public_key = st.session_state.ecc_private_key.public_key()

if "aes_key" not in st.session_state:
    st.session_state.aes_key = os.urandom(32)

if "blowfish_key" not in st.session_state:
    st.session_state.blowfish_key = os.urandom(16)

# Function to get raw RSA and ECC public keys without headers
def get_rsa_public_key():
    # Get the PEM encoding of the public key (without the header/footer)
    pem = st.session_state.rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Remove the PEM header and footer
    pem = pem.decode("utf-8").strip().splitlines()[1:-1]
    return ''.join(pem)  # Join the remaining parts to get the raw key

def get_ecc_public_key():
    # Get the PEM encoding of the public key (without the header/footer)
    pem = st.session_state.ecc_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Remove the PEM header and footer
    pem = pem.decode("utf-8").strip().splitlines()[1:-1]
    return ''.join(pem)  # Join the remaining parts to get the raw key

# Define Encryption Classes
class RSAEncryption:
    @staticmethod
    def encrypt(plaintext: str) -> str:
        encrypted = st.session_state.rsa_public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted.hex()

    @staticmethod
    def decrypt(encrypted_text: str) -> str:
        decrypted = st.session_state.rsa_private_key.decrypt(
            bytes.fromhex(encrypted_text),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

class ECCEncryption:
    @staticmethod
    def encrypt(plaintext: str) -> str:
        shared_key = st.session_state.ecc_private_key.exchange(ec.ECDH(), st.session_state.ecc_public_key)
        derived_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt',
            iterations=100000,
            backend=default_backend()
        ).derive(shared_key)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return iv.hex() + encrypted.hex() + encryptor.tag.hex()

    @staticmethod
    def decrypt(encrypted_text: str) -> str:
        iv = bytes.fromhex(encrypted_text[:24])
        tag = bytes.fromhex(encrypted_text[-32:])
        encrypted_data = bytes.fromhex(encrypted_text[24:-32])
        shared_key = st.session_state.ecc_private_key.exchange(ec.ECDH(), st.session_state.ecc_public_key)
        derived_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt',
            iterations=100000,
            backend=default_backend()
        ).derive(shared_key)
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted.decode()

class AESEncryption:
    @staticmethod
    def encrypt(plaintext: str) -> str:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(st.session_state.aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return iv.hex() + encrypted.hex() + encryptor.tag.hex()

    @staticmethod
    def decrypt(encrypted_text: str) -> str:
        iv = bytes.fromhex(encrypted_text[:32])
        tag = bytes.fromhex(encrypted_text[-32:])
        encrypted_bytes = bytes.fromhex(encrypted_text[32:-32])
        cipher = Cipher(algorithms.AES(st.session_state.aes_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_bytes) + decryptor.finalize()
        return decrypted.decode()

class BlowfishEncryption:
    @staticmethod
    def encrypt(plaintext: str) -> str:
        iv = os.urandom(8)
        cipher = Cipher(algorithms.Blowfish(st.session_state.blowfish_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return iv.hex() + encrypted.hex()

    @staticmethod
    def decrypt(encrypted_text: str) -> str:
        iv = bytes.fromhex(encrypted_text[:16])
        encrypted_bytes = bytes.fromhex(encrypted_text[16:])
        cipher = Cipher(algorithms.Blowfish(st.session_state.blowfish_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(64).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        return decrypted.decode()

# Function to regenerate keys
def generate_new_keys():
    st.session_state.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    st.session_state.rsa_public_key = st.session_state.rsa_private_key.public_key()
    st.session_state.ecc_private_key = ec.generate_private_key(ec.SECP256R1())
    st.session_state.ecc_public_key = st.session_state.ecc_private_key.public_key()
    st.session_state.aes_key = os.urandom(32)
    st.session_state.blowfish_key = os.urandom(16)

# Sidebar Key Management
if st.sidebar.button("Generate New Keys"):
    generate_new_keys()

# Display Key Information
algorithm = st.selectbox("Choose Encryption Algorithm", ["RSA", "ECC", "AES", "Blowfish"])
action = st.radio("Choose Action", ["Encrypt", "Decrypt"])
plaintext = st.text_area("Enter Text to Encrypt/Decrypt")

# Show Key Option
show_key_option = st.selectbox("Show Key", ["No", "Yes"])

if show_key_option == "Yes":
    key_map = {
        "RSA": ("RSA Public Key", get_rsa_public_key()),
        "ECC": ("ECC Public Key", get_ecc_public_key()),
        "AES": ("AES Key", st.session_state.aes_key.hex()),
        "Blowfish": ("Blowfish Key", st.session_state.blowfish_key.hex())
    }
    label, key = key_map[algorithm]
    st.write(label)
    
    # Display the key
    st.text_area("Key", key, height=150)
    
    # Add the copy button
    if st.button(f"Copy {label} to Clipboard"):
        pyperclip.copy(key)  # Copy the key to clipboard
        st.success(f"{label} copied to clipboard!")

# Encrypt/Decrypt Button
if st.button("Process"):
    if action == "Encrypt":
        result = globals()[algorithm + "Encryption"].encrypt(plaintext)
    else:
        result = globals()[algorithm + "Encryption"].decrypt(plaintext) if all(c in "0123456789abcdefABCDEF" for c in plaintext) else "Invalid hexadecimal input."
    
    # Store the result in session state to preserve it after re-run
    st.session_state.result = result

# Display the result from session state
if "result" in st.session_state:
    st.subheader("Result")
    st.text_area("", st.session_state.result, height=150)  # Use text_area to display result

    # Add a button to copy result to clipboard
    if st.button("Copy Result to Clipboard"):
        pyperclip.copy(st.session_state.result)  # Copy the result to clipboard
        st.success("Result copied to clipboard!")
