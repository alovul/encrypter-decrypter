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
        **🔐 RSA (Rivest-Shamir-Adleman) Encryption**

        **📜 History**
        - Developed in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman.
        - First widely adopted public-key encryption algorithm.

        **🧠 Mathematical Foundation**
        - Based on the computational difficulty of factoring large integers.
        - Steps:
            1. Choose large primes p and q.
            2. Compute n = p × q.
            3. Calculate φ(n) = (p−1)(q−1).
            4. Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1.
            5. Compute private exponent d where d ≡ e⁻¹ mod φ(n).
        - Public Key: (e, n)
        - Private Key: (d, n)
        - Encryption: C = M^e mod n
        - Decryption: M = C^d mod n

        **📦 Key Sizes**
        - Common: 2048-bit, 3072-bit, 4096-bit.
        - Larger keys provide better security but impact performance.

        **🔐 Applications**
        - Digital signatures
        - SSL/TLS certificates
        - Secure key exchange

        **✅ Pros**
        - Mature and widely trusted
        - Supports digital signatures and encryption
        - Asymmetric (no pre-shared secret required)

        **⚠️ Cons**
        - Very slow for encrypting large data
        - Large keys are required for strong security
        - Insecure if implemented without padding (use OAEP/PSS)
        - Vulnerable to quantum computing (Shor's algorithm)

        **🧪 Security Notes**
        - Never use textbook RSA (raw mod exponentiation)
        - Use padding schemes: OAEP (encryption), PSS (signing)
    """,

    "ECC": """
        **📐 Elliptic Curve Cryptography (ECC)**

        **📜 History**
        - Introduced in 1985 by Neal Koblitz and Victor S. Miller.
        - Became popular as an alternative to RSA with smaller keys.

        **🧠 Mathematical Foundation**
        - Based on algebraic structure of elliptic curves over finite fields.
        - Equation: y² = x³ + ax + b (mod p)
        - Secure due to the difficulty of the Elliptic Curve Discrete Logarithm Problem (ECDLP).
        - Uses point multiplication: Q = d × P, where:
            - d = private key
            - P = base point (curve generator)
            - Q = public key

        **🔑 Key Exchange**
        - Typically uses Elliptic Curve Diffie-Hellman (ECDH)
        - Also used in ECDSA for digital signatures

        **📦 Key Sizes**
        - 256-bit ECC ≈ 3072-bit RSA in strength
        - Common curves: secp256r1 (NIST P-256), secp384r1, Curve25519

        **🔐 Applications**
        - TLS handshakes
        - Blockchain/cryptocurrency wallets
        - Secure messaging (e.g., Signal, WhatsApp)

        **✅ Pros**
        - Smaller keys = faster computation
        - Lower power/resource usage (great for mobile/IoT)
        - Shorter signatures and ciphertexts

        **⚠️ Cons**
        - Implementation complexity
        - Need for careful curve selection (some NIST curves have been criticized)
        - Less understood than RSA by general public

        **🧪 Security Notes**
        - Use well-reviewed curves (Curve25519, NIST P-256)
        - Avoid custom or proprietary curves unless peer-reviewed
    """,

    "AES": """
        **🧊 Advanced Encryption Standard (AES)**

        **📜 History**
        - Standardized by NIST in 2001, replacing DES.
        - Originally known as Rijndael (designed by Daemen & Rijmen).

        **🧠 Mathematical Foundation**
        - Symmetric key block cipher
        - Works on 128-bit blocks
        - Key sizes: 128, 192, or 256 bits
        - Structure: Substitution-Permutation Network (SPN)
        - Number of rounds: 10 (AES-128), 12 (AES-192), 14 (AES-256)
        - Involves byte substitution, row shifting, column mixing, and round key addition

        **🔁 Modes of Operation**
        - ECB: Fast but insecure (reveals patterns)
        - CBC: Requires IV, popular but no built-in integrity
        - GCM: Authenticated encryption (confidentiality + integrity)
        - CTR: Stream mode, fast, but needs nonce management

        **📦 Key Management**
        - Critical to secure storage and handling of keys
        - Often used in hybrid systems (AES key exchanged via RSA or ECC)

        **🔐 Applications**
        - File/disk encryption (BitLocker, FileVault)
        - Encrypted databases
        - HTTPS traffic (via TLS)

        **✅ Pros**
        - Fast and efficient for large data
        - Hardware acceleration available (AES-NI)
        - Strong resistance to known attacks when properly used

        **⚠️ Cons**
        - No forward secrecy in itself
        - Sensitive to key leakage and side-channel attacks
        - Padding oracle attacks if CBC is misused

        **🧪 Security Notes**
        - Use AES-GCM for authenticated encryption
        - Use secure random IVs (never reuse them in CTR/GCM)
        - 128-bit key is still considered secure in 2025, but 256-bit is recommended for top-tier security
    """,

    "Blowfish": """
        **🐡 Blowfish Cipher**

        **📜 History**
        - Designed in 1993 by Bruce Schneier.
        - Meant as a fast, free alternative to DES.

        **🧠 Mathematical Foundation**
        - 64-bit block cipher using Feistel structure
        - Key size: 32–448 bits
        - 16 rounds of encryption per block
        - Key schedule creates 18 32-bit subkeys and four 32-bit S-boxes
        - Operates by mixing key material into P-array and S-boxes using repeated encryption

        **🔁 Modes of Operation**
        - Often used in CBC, ECB, or CFB modes
        - No built-in authentication or integrity checking

        **📦 Key Schedule**
        - Known to be slow due to expensive setup
        - Key-dependent S-box generation makes Blowfish hard to parallelize

        **🔐 Applications**
        - bcrypt password hashing algorithm
        - Legacy file encryption tools
        - Embedded systems with limited memory

        **✅ Pros**
        - Free to use, no patents
        - Strong for its time and configurable key size
        - Compact implementation (especially useful in embedded contexts)

        **⚠️ Cons**
        - 64-bit block size is now considered insecure for modern applications
        - Vulnerable to birthday attacks at scale
        - No support for authenticated encryption
        - Slower than AES in many real-world scenarios

        **🧪 Security Notes**
        - Superseded by Twofish (also by Schneier) and AES
        - Still used in `bcrypt`, but not recommended for encryption today
        - Consider AES, ChaCha20, or Twofish for new implementations
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

if "result" in st.session_state:
    st.subheader("📤 Output")
    st.text_area("Processed Output", st.session_state.result, height=150)
    if st.button("📋 Copy Result"):
        pyperclip.copy(st.session_state.result)
        st.success("Result copied to clipboard!")

st.divider()

st.subheader("🔐 Key Options")

# Track key viewer state
if "selected_key_algo" not in st.session_state:
    st.session_state.selected_key_algo = algorithm  # match selected algorithm by default

# Keep the selected key viewer synced to the encryption algorithm
if st.session_state.selected_key_algo != algorithm:
    st.session_state.selected_key_algo = algorithm  # update when encryption method changes

# Key viewer toggle
view_key = st.checkbox("Show Key Viewer")

if view_key:
    # Available algorithms
    algo_list = ["RSA", "ECC", "AES", "Blowfish"]
    
    # Show the key dropdown with the active algorithm pre-selected
    key_choice = st.selectbox(
        "🔑 Select Key to View",
        algo_list,
        index=algo_list.index(st.session_state.selected_key_algo),
        key="key_choice"
    )

    # Key lookup table
    key_map = {
        "RSA": ("RSA Public Key", get_rsa_public_key()),
        "ECC": ("ECC Public Key", get_ecc_public_key()),
        "AES": ("AES Key", st.session_state.aes_key.hex()),
        "Blowfish": ("Blowfish Key", st.session_state.blowfish_key.hex())
    }

    label, key_val = key_map[key_choice]
    st.text_area(label, key_val, height=150)

    if st.button(f"📋 Copy {label}"):
        pyperclip.copy(key_val)
        st.success(f"{label} copied to clipboard!")





