import streamlit as st
import hashlib
import json
import os
import time
from crytography.fernet import Fernet
from base64 import urlsafe_b64decode
from hashlib import pbkdf2_hmac

DATA_FILE = "secure.json"
SALT = b"secure_salt_value"
LOGOUT_DURATION = 60