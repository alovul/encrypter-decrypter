import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip


# Streamlit Page Config
st.set_page_config(page_title="🔐 Crypto Toolkit", layout="wide")
if "sidebar_expanded" not in st.session_state:
    st.session_state.sidebar_expanded = False

with st.sidebar:
    if st.button("🧩 Toggle Sidebar Width"):
        st.session_state.sidebar_expanded = not st.session_state.sidebar_expanded

st.markdown("""
    <style>
        .main { background-color: #f9f9f9; }
        .stTextArea textarea { font-family: monospace; }
    </style>
""", unsafe_allow_html=True)

# Title
st.title("🔐 Encryptor/Decryptor")
st.markdown("""
    <style>
    .main { background-color: #f9f9f9; }
    .stTextArea textarea { font-family: monospace; }
    section[role="region"] > div[aria-expanded="true"] {
        border: 2px solid #6366F1;
        background-color: #EEF2FF;
        padding: 10px;
        border-radius: 10px;
    }
    /* Only expand sidebar to full width when a checkbox is triggered */
    .sidebar-expanded [data-testid="stSidebar"] {
        width: 100% !important;
        max-width: 100% !important;
    }
    .sidebar-expanded [data-testid="stSidebarContent"] {
        padding: 2rem;
    }
</style>
""", unsafe_allow_html=True)



if st.session_state.sidebar_expanded:
    st.markdown("""
        <style>
            [data-testid="stSidebar"] {
                width: 100% !important;
                max-width: 100% !important;
            }
            [data-testid="stSidebarContent"] {
                padding: 2rem;
            }
        </style>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
        <style>
            [data-testid="stSidebar"] {
                width: 18rem !important;
                max-width: 18rem !important;
            }
            [data-testid="stSidebarContent"] {
                padding: 1rem;
            }
        </style>
    """, unsafe_allow_html=True)



# Sidebar Algorithm Info
st.sidebar.title("🧠 Algorithm Details")
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
    with st.sidebar.expander(f"ℹ️ {algo}"):
        st.markdown(description)

# Key Initialization
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

# Key Display

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

# Encryption Classes
class RSAEncryption:
    @staticmethod
    def encrypt(plaintext):
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
    def decrypt(encrypted_text):
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
    def encrypt(plaintext):
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
    def decrypt(encrypted_text):
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
    def encrypt(plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(st.session_state.aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return iv.hex() + encrypted.hex() + encryptor.tag.hex()

    @staticmethod
    def decrypt(encrypted_text):
        iv = bytes.fromhex(encrypted_text[:32])
        tag = bytes.fromhex(encrypted_text[-32:])
        encrypted_bytes = bytes.fromhex(encrypted_text[32:-32])
        cipher = Cipher(algorithms.AES(st.session_state.aes_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_bytes) + decryptor.finalize()
        return decrypted.decode()

class BlowfishEncryption:
    @staticmethod
    def encrypt(plaintext):
        iv = os.urandom(8)
        cipher = Cipher(algorithms.Blowfish(st.session_state.blowfish_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return iv.hex() + encrypted.hex()

    @staticmethod
    def decrypt(encrypted_text):
        iv = bytes.fromhex(encrypted_text[:16])
        encrypted_bytes = bytes.fromhex(encrypted_text[16:])
        cipher = Cipher(algorithms.Blowfish(st.session_state.blowfish_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(64).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        return decrypted.decode()

# Key Generation

def generate_new_keys():
    st.session_state.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    st.session_state.rsa_public_key = st.session_state.rsa_private_key.public_key()
    st.session_state.ecc_private_key = ec.generate_private_key(ec.SECP256R1())
    st.session_state.ecc_public_key = st.session_state.ecc_private_key.public_key()
    st.session_state.aes_key = os.urandom(32)
    st.session_state.blowfish_key = os.urandom(16)

if st.sidebar.button("🔁 Generate New Keys"):
    generate_new_keys()
    st.sidebar.success("Keys regenerated successfully!")

# UI Layout
col1, col2 = st.columns([1, 1])
with col1:
    algorithm = st.selectbox("🔽 Choose Algorithm", ["RSA", "ECC", "AES", "Blowfish"])
with col2:
    action = st.radio("⚙️ Action", ["Encrypt", "Decrypt"], horizontal=True)

st.divider()

if "clear_input" not in st.session_state:
    st.session_state.clear_input = False
st.subheader("📝 Input Text")
default_text = "" if st.session_state.clear_input else st.session_state.get("input_text", "")
st.text_area("Enter your text here:", key="input_text", value=default_text, height=150, placeholder="Type your message...")
st.session_state.clear_input = False  # Reset flag

st.divider()

if st.button("🚀 Process Now"):
    try:
        input_val = st.session_state.input_text
        if action == "Encrypt":
            result = globals()[algorithm + "Encryption"].encrypt(input_val)
        else:
            result = globals()[algorithm + "Encryption"].decrypt(input_val) if all(c in "0123456789abcdefABCDEF" for c in input_val) else "Invalid hexadecimal input."
        st.session_state.result = result
        st.session_state.clear_input = True  # Will clear input on next rerun
    except Exception as e:
        st.error(f"❌ Error during processing: {e}")


st.divider()

st.subheader("🔐 Key Options")
show_key = st.selectbox("Do you want to view the key?", ["No", "Yes"])
if show_key == "Yes":
    key_map = {
        "RSA": ("RSA Public Key", get_rsa_public_key()),
        "ECC": ("ECC Public Key", get_ecc_public_key()),
        "AES": ("AES Key", st.session_state.aes_key.hex()),
        "Blowfish": ("Blowfish Key", st.session_state.blowfish_key.hex())
    }
    label, key_val = key_map[algorithm]
    st.text_area(label, key_val, height=150)
    if st.button(f"📋 Copy {label}"):
        pyperclip.copy(key_val)
        st.success(f"{label} copied to clipboard!")

st.divider()

if "result" in st.session_state:
    st.subheader("📤 Output")
    st.text_area("Processed Output", st.session_state.result, height=150)
    if st.button("📋 Copy Result"):
        pyperclip.copy(st.session_state.result)
        st.success("Result copied to clipboard!")
