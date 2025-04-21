import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
import streamlit.components.v1 as components

# Constants
DATA_FILE = "secure.json"
SALT = b"secure_salt_value"
LOGOUT_DURATION = 60

# Session states
if 'authenticated_user' not in st.session_state:
    st.session_state.authenticated_user = None
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0

# Load & Save Data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

# Key generation and password hashing
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000, dklen=32)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# Encryption & Decryption
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(token, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(token.encode()).decode()
    except:
        return None

# Load existing user data
store_data = load_data()

# UI Starts
st.title("🛡️ Secure Data Encryption System")
menu = ['🏠 Home', '📝 Register', '🔐 Login', '💾 Store Data', '🔍 Retrieve Data']
st.sidebar.markdown("## 📌 Navigation")
choice = st.sidebar.selectbox("", menu)

# Home Page
if choice == "🏠 Home":
    st.subheader("👋 Welcome to the Secure Data Encryption System!")
    st.markdown("""
🔐 **Features**:
- Encrypt your sensitive data with a custom passkey 🔑  
- Decrypt it only with the correct key 🔓  
- 3 wrong login attempts = 60s lockout 🔥  
- No external database used — all local & secure 💾  
""")

# Registration
elif choice == "📝 Register":
    st.subheader("🆕 Register New User")
    username = st.text_input("👤 Choose Username")
    password = st.text_input("🔑 Choose Password", type='password')

    if st.button("✅ Register"):
        if username and password:
            if username in store_data:
                st.warning("⚠️ Username already exists!")
            else:
                store_data[username] = {
                    'password': hash_password(password),
                    'data': []
                }
                save_data(store_data)
                st.success("🎉 User registered successfully!")
        else:
            st.error("❌ Both fields are required!")

# Login
elif choice == "🔐 Login":
    st.subheader("🔓 Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type='password')

    if st.button("🔓 Login"):
        if username in store_data and store_data[username]['password'] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! {remaining} attempt(s) left.")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOGOUT_DURATION
                st.error("🚫 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# Store Encrypted Data
elif choice == "💾 Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("📥 Store Encrypted Data")
        
        # Data Input Field (Sensitive Data)
        data = st.text_area("✍️ Enter data to encrypt", placeholder="Type your sensitive data here...")

        # Passphrase Input Field (Encryption Key)
        passkey = st.text_input("🔑 Enter encryption key (passphrase)", type='password', placeholder="Enter a strong passphrase")

        # Encrypt and Save Button
        if st.button("🔐 Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                store_data[st.session_state.authenticated_user]['data'].append(encrypted)
                save_data(store_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("❌ Both fields are required!")

# Retrieve and Decrypt Data
elif choice == "🔍 Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("📤 Retrieve Encrypted Data")
        user_data = store_data.get(st.session_state.authenticated_user, {}).get('data', [])

        if not user_data:
            st.info("ℹ️ No data found.")
        else:
            st.write("🔒 Encrypted Entries:")
            for i, item in enumerate(user_data):
                unique_id = f"encrypted_{i}"
                # Display encrypted data in a text area for easy copying
                st.text_area(f"🔐 Encrypted Entry {i+1}", item, key=unique_id)

            encrypted_input = st.text_area("🔑 Enter encrypted text to decrypt")
            passkey = st.text_input("🔓 Enter decryption key", type='password')

            if st.button("🔍 Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success("✅ Decryption Successful!")
                    st.code(result, language="text")
                else:
                    st.error("❌ Decryption failed. Incorrect passkey or invalid data.")
