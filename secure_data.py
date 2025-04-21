import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

DATA_FILE = "secure.json"
SALT = b"secure_salt_value"
LOGOUT_DURATION = 60

if 'authendicate_user' not in st.session_state:
    st.session_state.authendicate_user = None
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0

#* if data is load 
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE,'r') as f:
            return json.load(f)
    return {}

def save_data(data):
        with open(DATA_FILE,'w') as f:
             json.dump(data,f)


def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000, dklen=32)
    return urlsafe_b64encode(key)

def hash_password(password):
     return hashlib.pbkdf2_hmac('sha256',password.encode(),SALT, 10000).hex()
  
#* cryptography.fernet used
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(token, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(token.encode()).decode()
    except:
        return None


store_data = load_data()

st.title("🛡️ Secure Data Encryption System Using Streamlit")
menu = ['home','register','login','store data','retrive data']
choice = st.sidebar.selectbox("Navigation",menu)


if choice == "home":
     st.subheader("Welcome Data Encryption System Using Streamlit")
     st.markdown(f"""
Develop a Streamlit-based secure data storage and retrieval system where:
                 
Users store data with a unique passkey.
Users decrypt data by providing the correct passkey.
Multiple failed attempts result in a forced reauthorization (login page).
The system operates entirely in memory without external databases.
""")
elif choice == "register":
     st.subheader("register new user")
     username = st.text_input("Choose Username ")
     password = st.text_input("Choose Password ",type='password')

     if st.button("Register"):
          if username and password:
               if username in store_data:
                    st.warning("Already Exit")
               else:
                    store_data[username] = {
                         'password' : hash_password(password),
                         'data' : []
                    }
                    save_data(store_data)
                    st.success("User register sucessfully")

          else:
               st.error("Both field required")
elif choice == 'login':
     st.subheader("Login")
     if time.time()<st.session_state.lockout_time:
          remaining =  int(st.session_state.lockout_time - time.time())
          st.error(f"Too many field attempts. please wait {remaining} seconds.")
          st.stop()
     username = st.text_input("Username")
     password = st.text_input("Password",type='password')

     if st.button("login"):
          if username in store_data and store_data[username]['password'] == hash_password(password):
               st.session_state.authendicate_user = username
               st.session_state.failed_attempts = 0
               st.success(f"Welcome {username}!")
          else:
               st.session_state.failed_attempts += 1
               remaining = 3 - st.session_state.failed_attempts
               st.error(f"Invalid error credential! Attempt {remaining} left")
               if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOGOUT_DURATION
                    st.error("To many failed attempts. locked for 60 second")
                    st.stop()

#  data store section
elif choice == 'store data':
     if not st.session_state.authendicate_user:
          st.warning("Please forst login")
     else:
          st.subheader("Store Encrpty data ")
          data = st.text_area("Enter data to encrypt")
          passkey = st.text_input("Encryption key(passphrase)",type="password")

          if st.button("Encrypt ANd save"):
               if data and passkey:
                    encrpyt = encrypt_text(data,passkey)
                    store_data[st.session_state.authendicate_user]['data'].append(encrpyt)
                    save_data(store_data)
                    st.success("data encrypt ans save data")
                
# data retrive section
elif choice == 'retrive data':
     if not st.session_state.authendicate_user:
          st.warning("Please first login")
     else:
          st.subheader("Retrive data")
          user_data = store_data.get(st.session_state.authendicate_user,{}).get('data',{})

          if not user_data:
               st.info("No data Found")

               


               
               