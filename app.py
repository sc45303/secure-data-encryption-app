
import streamlit as st
import hashlib
import json
import os
from datetime import timedelta
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode  
from hashlib import pbkdf2_hmac
import time

# 🛡️ Configuration Constants
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60  # seconds

# 🧑💻 User Session Management
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:  # Fixed typo: 'attempt' -> 'attempts'
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# 📂 Data Handling Functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key).decode()  # Fixed base64 encoding

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# 🔐 Cryptography Functions
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# 🧭 Navigation
st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]  # Fixed typo
choice = st.sidebar.selectbox("🚀 Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to Secure Data Encryption System")
    st.markdown("""
    ### 📖 User Guide:
    1. **👤 Register** - Create new account
    2. **🔑 Login** - Access your secure vault
    3. **💾 Store Data** - Encrypt sensitive information
    4. **📤 Retrieve Data** - Decrypt your secured data
    
    🔐 All data is encrypted using military-grade AES-256 encryption
    """)

elif choice == "Register":
    st.subheader("📝 User Registration")
    username = st.text_input("👤 Choose Username")
    password = st.text_input("🔑 Choose Password", type="password")

    if st.button("🚀 Register Account"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists!")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("🎉 Account created successfully!")
        else:
            st.error("❌ All fields are required!")

elif choice == "Login":
    st.subheader("🔑 User Authentication")
    
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Account locked! Please try again in {remaining} seconds")
        st.stop()

    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type="password")

    if st.button("🚪 Login"):
        user_data = stored_data.get(username)
        if user_data and user_data["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"🎉 Welcome back {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! {remaining} attempts remaining")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION  # Fixed calculation
                st.error("🔒 Account locked for 60 seconds due to multiple failed attempts")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please login first!")
    else:
        st.subheader("🔒 Data Encryption")
        data = st.text_area("📝 Enter sensitive data to encrypt")
        passkey = st.text_input("🔑 Encryption passphrase", type="password")

        if st.button("🔐 Encrypt & Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and stored securely!")
            else:
                st.error("❌ Both fields are required!")

elif choice == "Retrieve Data":  # Fixed typo
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please login first!")
    else:
        st.subheader("🔓 Data Decryption")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No encrypted data found!")
        else:
            st.write("📦 Stored Encrypted Items:")
            for i, item in enumerate(user_data):
                with st.expander(f"🔒 Encrypted Item {i+1}"):
                    st.code(item)
                    passkey = st.text_input(f"🔑 Enter passkey for Item {i+1}", 
                                         type="password", 
                                         key=f"passkey_{i}")
                    
                    if st.button(f"🔓 Decrypt Item {i+1}", key=f"decrypt_{i}"):
                        result = decrypt_text(item, passkey)
                        if result:
                            st.success(f"📄 Decrypted Content:\n{result}")
                        else:
                            st.error("❌ Invalid passkey or corrupted data!")
