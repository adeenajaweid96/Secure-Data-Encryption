import streamlit as st
# import json
# import os
import hashlib
import time
from cryptography.fernet import Fernet
import base64

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "stored_data" not in st.session_state:
    st.session_state.stored_data = { } 
if "current_page" not in st.session_state:
    st.session_state.current_page = "Home"
if "last_attempt_time" not in st.session_state:
    st.session_state.last_attempt_time = 0           

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_data(text,passkey):
    key = generate_key(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypt_text,passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]["passkey"] == hashed_passkey:
            key = generate_key(passkey)
            cipher = Fernet(key)
            decrypt = cipher.decrypt(encrypt_text.encode()).decode()
            st.session_state.failed_attempts = 0 
            return decrypt
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception as e:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

def generate_id():
    import uuid
    return str(uuid.uuid4())

def reset_failed_attempt():
    st.session_state.failed_attempts = 0

def change_page(page):
    st.session_state.current_page = page

st.title("Secure Data Encrypt System🔏")

menu = ["Home","Store Data","Retrieve Data","Login"]
choice = st.sidebar.selectbox("Navigation",menu , index=menu.index(st.session_state.current_page))

st.session_state.current_page = choice

if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("Too many failed attempts! Reauthoriation required🔒")


if st.session_state.current_page == "Home":
    st.subheader("Welcome to the Secure Data System🔐")
    st.write("Use this app to secure your retrieve data with unique passkey")

    col1 , col2 = st.columns(2)
    with col1:
        if st.button("Store New data",use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("Retrieve Data",use_container_width=True):
            change_page("Retrieve Data")        
    st.info(f"Currently storing {len(st.session_state.stored_data)} encrypted data entries")

elif st.session_state.current_page == "Store Data":
    st.subheader("Store Data Securely 🔏")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter passkey",type="password",key="password")
    confirm_passkey = st.text_input("Enter confirm passkey",type="password",key="confirm_password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.warning("Paaskey doesn't match❌")
            else:
                data_id = generate_id()
                hashed_passkey = hash_passkey(passkey)

                encrypted_text =encrypt_data(user_data,passkey) 

                st.session_state.stored_data[data_id]={
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }   

                st.success("Data stored Successfully✔")

                st.code(data_id,language="text")
                st.info("Save this Data id! You'll need to retrieve your data")
        else:
            st.error("All Fields must required!")

elif st.session_state.current_page == "Retrieve Data":
    st.subheader("Retrieve Your Data")


    attempts_remaining = 3- st.session_state.failed_attempts
    st.info(f"Attempts Remaining: {attempts_remaining}")

    data_id = st.text_input("Enter ID:")
    passkey = st.text_input("Enter Passkey:",type="password")

    if st.button("Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
             encrypted_text =  st.session_state.stored_data[data_id]["encrypted_text"]
             decrypted_text = decrypt_data(encrypted_text,passkey, data_id)

             if decrypted_text:
                 st.success("Decryption Successfull")
                 st.markdown("*** Your Decrypted Data:")
                 st.code(decrypted_text,language="text")
             else:
                 st.warning(f"❌Incorrect passkey! Attempts Remaining {3 - st.session_state.failed_attempts}")
        else:
            st.error("❌Data ID not found!")

        if st.session_state.failed_attempts >= 3:
            st.warning("Enough Failed Attempts! Redirecting to Login Page.")
            st.session_state.current_page ="Login"
            st.rerun()    
    else:
        st.error("⚠️Both Fields are required")

elif st.session_state.current_page == "Login":
    st.subheader("Reauthorization Required!")

    if time.time() - st.session_state.last_attempt_time < 10 and st.session_state.failed_attempts  >= 3:
        remaining_time = int(10 -(time.time() - st.session_state.last_attempt_time))
        st.warning(f"Pease wait {remaining_time} seconds before trying")

    else:
        login_pass = st.text_input("Enter Master Password: ",type="password") 


        if st.button("Login"):
         if login_pass == "password123":
            reset_failed_attempt()
            st.success("✅ Reauthorized successfully!")
            st.session_state.current_page = "Home"
            # st.rerun() 
         else:
            st.error("❌ Incorrect password!")                 

st.markdown("----")
st.markdown("Secure Data Encrypted System")