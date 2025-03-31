import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
        
        **Pros**:
        - High security for large key sizes
        - Widely used and trusted
        
        **Cons**:
        - Slow for large data encryption
        - Large key sizes needed for strong security
    """,
    "ECC": """
        **Elliptic Curve Cryptography (ECC)**
        
        **History**: Introduced in 1985 by Neal Koblitz and Victor Miller as an alternative to RSA.
        
        **Mathematical Foundation**:
        - Based on the equation: y² ≡ x³ + ax + b (mod p)
        - Key generation uses elliptic curve point multiplication.
        - Encryption typically uses ECDH for shared secret generation.
        
        **Pros**:
        - Strong security with smaller key sizes compared to RSA
        - Efficient for mobile and low-power devices
        
        **Cons**:
        - More complex implementation
        - Limited support in legacy systems
    """,
    "AES": """
        **Advanced Encryption Standard (AES)**
        
        **History**: Developed by Belgian cryptographers Vincent Rijmen and Joan Daemen in 2001.
        
        **Mathematical Foundation**:
        - Operates on fixed-size blocks of data (128-bits).
        - Uses substitution-permutation networks and rounds of encryption.
        
        **Pros**:
        - Fast and efficient for data encryption
        - Widely adopted for secure communication
        
        **Cons**:
        - Requires secure key management
        - Limited by block size (128 bits)
    """,
    "Blowfish": """
        **Blowfish Cipher**
        
        **History**: Designed in 1993 by Bruce Schneier as a fast and secure block cipher.
        
        **Mathematical Foundation**:
        - Operates on a 16-round Feistel network.
        - Key expansion generates 18 subkeys and four S-boxes.
        
        **Pros**:
        - Fast encryption with a flexible key length (32–448 bits)
        - Good performance on low-power devices
        
        **Cons**:
        - Outdated for modern security needs
        - Considered less secure than AES for long-term use
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
    pem = st.session_state.rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem = pem.decode("utf-8").strip().splitlines()[1:-1]
    return ''.join(pem)

def get_ecc_public_key():
    pem = st.session_state.ecc_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem = pem.decode("utf-8").strip().splitlines()[1:-1]
    return ''.join(pem)


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

# Handle the input text
if 'plaintext' not in st.session_state:
    st.session_state.plaintext = ""

# Text area for input
plaintext = st.text_area("Enter Text to Encrypt/Decrypt", value=st.session_state.plaintext)

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
    st.text_area("Key (Click to Copy)", key, height=150)

# Encrypt/Decrypt Button
if st.button("Process"):
    if action == "Encrypt":
        result = globals()[algorithm + "Encryption"].encrypt(plaintext)
    else:
        result = globals()[algorithm + "Encryption"].decrypt(plaintext) if all(c in "0123456789abcdefABCDEF" for c in plaintext) else "Invalid hexadecimal input."
    
    # Store the result in session state to preserve it after re-run
    st.session_state.result = result

    # Reset the plaintext field in session state to clear the input text
    st.session_state.plaintext = ""  # Clear the input text after processing

# Display the result from session state
if "result" in st.session_state:
    st.subheader("Result")
    st.text_area("", st.session_state.result, height=150)  # Use text_area to display result

    # Add a button to copy result to clipboard
    st.markdown(f"""
        <button onclick="navigator.clipboard.writeText('{st.session_state.result}')">Copy Result to Clipboard</button>
    """, unsafe_allow_html=True)
