import streamlit as st
import hashlib
import base64
import time
from cryptography.fernet import Fernet
import secrets
import string
import io
import json

# Set page configuration
st.set_page_config(
    page_title="Secure Data Encryption",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E88E5;
        text-align: center;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #424242;
        text-align: center;
        margin-bottom: 2rem;
    }
    .success-text {
        color: #4CAF50;
        font-weight: bold;
    }
    .warning-text {
        color: #FFC107;
        font-weight: bold;
    }
    .error-text {
        color: #F44336;
        font-weight: bold;
    }
    .info-box {
        background-color: #E3F2FD;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .stButton>button {
        width: 100%;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state variables if they don't exist
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'current_page' not in st.session_state:
    st.session_state.current_page = 'home'

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'max_attempts' not in st.session_state:
    st.session_state.max_attempts = 3

if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = True

if 'temp_data_key' not in st.session_state:
    st.session_state.temp_data_key = None

if 'decrypted_file' not in st.session_state:
    st.session_state.decrypted_file = None

# Security functions
def hash_passkey(passkey):
    """Hash a passkey using SHA-256"""
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    """Generate a Fernet key from a passkey"""
    # We need a 32-byte key for Fernet
    hashed = hashlib.sha256(passkey.encode()).digest()
    # Convert to base64 as required by Fernet
    return base64.urlsafe_b64encode(hashed)

def encrypt_data(data, passkey, is_file=False, filename=None):
    """
    Encrypt data using Fernet encryption
    
    Args:
        data: The data to encrypt (string or bytes)
        passkey: The passkey to use for encryption
        is_file: Whether the data is a file
        filename: The name of the file (if is_file is True)
        
    Returns:
        bytes: The encrypted data
    """
    key = generate_key_from_passkey(passkey)
    cipher_suite = Fernet(key)
    
    if is_file:
        # For files, we need to store metadata along with the file content
        metadata = {
            "is_file": True,
            "filename": filename,
            "content": base64.b64encode(data).decode()
        }
        data_to_encrypt = json.dumps(metadata).encode()
    else:
        # For text, just encrypt the text directly
        data_to_encrypt = data.encode() if isinstance(data, str) else data
    
    encrypted_data = cipher_suite.encrypt(data_to_encrypt)
    return encrypted_data

def decrypt_data(encrypted_data, passkey):
    """
    Decrypt data using Fernet encryption
    
    Args:
        encrypted_data: The encrypted data
        passkey: The passkey to use for decryption
        
    Returns:
        tuple: (decrypted_data, is_file, filename)
            - decrypted_data: The decrypted data (string or bytes)
            - is_file: Whether the data is a file
            - filename: The name of the file (if is_file is True)
    """
    try:
        key = generate_key_from_passkey(passkey)
        cipher_suite = Fernet(key)
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        
        # Try to parse as JSON to check if it's a file
        try:
            metadata = json.loads(decrypted_data.decode())
            if isinstance(metadata, dict) and metadata.get("is_file", False):
                # It's a file, return the file content and metadata
                filename = metadata.get("filename", "unknown_file")
                file_content = base64.b64decode(metadata.get("content", ""))
                return file_content, True, filename
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Not JSON, so it's probably just text
            pass
        
        # If we get here, it's just text
        return decrypted_data.decode(), False, None
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None, False, None

def generate_secure_passkey(length=12):
    """Generate a secure random passkey"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Navigation functions
def navigate_to(page):
    """Navigate to a specific page"""
    st.session_state.current_page = page

# Page components
def home_page():
    """Home page with options to store or retrieve data"""
    st.markdown("<h1 class='main-header'>Secure Data Encryption</h1>", unsafe_allow_html=True)
    st.markdown("<p class='sub-header'>Store and retrieve your encrypted data securely</p>", unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Store New Data", use_container_width=True):
            navigate_to('insert_data')
    
    with col2:
        if st.button("Retrieve Data", use_container_width=True):
            navigate_to('retrieve_data')
    
    # Display stored data keys (not the data itself)
    if st.session_state.stored_data:
        st.markdown("### Stored Data Keys")
        for key in st.session_state.stored_data.keys():
            item = st.session_state.stored_data[key]
            icon = "📄" if item.get("is_file", False) else "📝"
            st.markdown(f"- {icon} {key}")
    else:
        st.info("No data stored yet. Click 'Store New Data' to get started.")
    
    # Security information
    with st.expander("Security Information"):
        st.markdown("""
        ### How Your Data is Protected
        
        - **Encryption**: We use Fernet symmetric encryption, which is built on AES-128 in CBC mode with PKCS7 padding.
        - **Passkey Hashing**: Your passkeys are hashed using SHA-256 before storage.
        - **Authentication**: After 3 failed attempts, you'll need to re-authenticate.
        - **In-Memory Storage**: Data is stored in memory only and is not persisted to disk.
        - **File Encryption**: Files are encrypted with the same strong encryption as text data.
        
        ⚠️ **Important**: Remember your passkeys! There is no way to recover your data if you forget them.
        """)

def insert_data_page():
    """Page for inserting new encrypted data"""
    st.markdown("<h1 class='main-header'>Store Encrypted Data</h1>", unsafe_allow_html=True)
    
    # Input fields
    data_key = st.text_input("Data Label/Key", placeholder="e.g., 'my_secret_note'")
    
    # Add tabs for text and file upload
    tab1, tab2 = st.tabs(["Text Input", "File Upload"])
    
    with tab1:
        data_value = st.text_area("Data to Encrypt", placeholder="Enter the text you want to encrypt")
        is_file = False
        uploaded_file = None
    
    with tab2:
        uploaded_file = st.file_uploader("Upload File to Encrypt", type=None)
        if uploaded_file is not None:
            file_details = {"Filename": uploaded_file.name, "FileType": uploaded_file.type, "FileSize": f"{uploaded_file.size / 1024:.2f} KB"}
            st.json(file_details)
            is_file = True
            data_value = None
    
    passkey = st.text_input("Passkey", type="password", placeholder="Enter a strong passkey")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Generate Secure Passkey"):
            secure_passkey = generate_secure_passkey()
            st.session_state.temp_passkey = secure_passkey
            st.info(f"Generated Passkey: {secure_passkey}\n\nMake sure to save this passkey securely!")
    
    with col2:
        if st.button("Clear"):
            st.experimental_rerun()
    
    # Store data button
    if st.button("Encrypt and Store Data", type="primary", use_container_width=True):
        if not data_key:
            st.error("Data key is required!")
        elif data_key in st.session_state.stored_data:
            st.error(f"Data key '{data_key}' already exists. Please use a different key.")
        elif not passkey:
            st.error("Passkey is required!")
        elif (not data_value and not uploaded_file):
            st.error("Please enter text or upload a file to encrypt!")
        else:
            # Show a spinner during encryption
            with st.spinner("Encrypting data..."):
                # Encrypt and store the data
                if is_file and uploaded_file:
                    # Handle file upload
                    file_bytes = uploaded_file.getvalue()
                    encrypted_data = encrypt_data(file_bytes, passkey, is_file=True, filename=uploaded_file.name)
                    hashed_passkey = hash_passkey(passkey)
                    
                    st.session_state.stored_data[data_key] = {
                        "encrypted_text": encrypted_data,
                        "passkey": hashed_passkey,
                        "is_file": True,
                        "filename": uploaded_file.name
                    }
                else:
                    # Handle text input
                    encrypted_data = encrypt_data(data_value, passkey)
                    hashed_passkey = hash_passkey(passkey)
                    
                    st.session_state.stored_data[data_key] = {
                        "encrypted_text": encrypted_data,
                        "passkey": hashed_passkey,
                        "is_file": False
                    }
            
            st.success(f"Data '{data_key}' encrypted and stored successfully!")
            
            # Show a progress bar for visual feedback
            progress_bar = st.progress(0)
            for i in range(100):
                time.sleep(0.01)
                progress_bar.progress(i + 1)
            
            # Navigate back to home after successful storage
            time.sleep(0.5)
            navigate_to('home')
    
    # Back button
    if st.button("Back to Home", use_container_width=True):
        navigate_to('home')

def retrieve_data_page():
    """Page for retrieving and decrypting data"""
    st.markdown("<h1 class='main-header'>Retrieve Encrypted Data</h1>", unsafe_allow_html=True)
    
    # Check if there's any data to retrieve
    if not st.session_state.stored_data:
        st.warning("No encrypted data found. Please store some data first.")
        if st.button("Back to Home", use_container_width=True):
            navigate_to('home')
        return
    
    # Check if user is authenticated
    if not st.session_state.is_authenticated:
        st.error("You need to authenticate first due to too many failed attempts.")
        if st.button("Go to Authentication", use_container_width=True):
            navigate_to('login')
        return
    
    # Display failed attempts warning if any
    if st.session_state.failed_attempts > 0:
        st.warning(f"Failed attempts: {st.session_state.failed_attempts}/{st.session_state.max_attempts}")
    
    # Input fields
    data_keys = list(st.session_state.stored_data.keys())
    selected_key = st.selectbox("Select Data to Retrieve", data_keys)
    
    # Show file icon if it's a file
    if st.session_state.stored_data[selected_key].get("is_file", False):
        filename = st.session_state.stored_data[selected_key].get("filename", "unknown_file")
        st.info(f"📄 This is a file: {filename}")
    
    passkey = st.text_input("Enter Passkey", type="password", placeholder="Enter the passkey for this data")
    
    # Retrieve data button
    if st.button("Decrypt and Retrieve Data", type="primary", use_container_width=True):
        if not passkey:
            st.error("Passkey is required!")
        else:
            # Get the stored data
            stored_item = st.session_state.stored_data.get(selected_key)
            
            if not stored_item:
                st.error(f"Data '{selected_key}' not found!")
                return
            
            # Check if passkey is correct
            hashed_input_passkey = hash_passkey(passkey)
            stored_hashed_passkey = stored_item["passkey"]
            
            if hashed_input_passkey == stored_hashed_passkey:
                # Decrypt the data
                encrypted_text = stored_item["encrypted_text"]
                
                with st.spinner("Decrypting data..."):
                    decrypted_data, is_file, filename = decrypt_data(encrypted_text, passkey)
                
                if decrypted_data is not None:
                    # Reset failed attempts on success
                    st.session_state.failed_attempts = 0
                    
                    # Show a progress bar for visual feedback
                    progress_bar = st.progress(0)
                    for i in range(100):
                        time.sleep(0.01)
                        progress_bar.progress(i + 1)
                    
                    # Display the decrypted data
                    st.success("Data decrypted successfully!")
                    
                    if is_file and filename:
                        # Handle file download
                        st.markdown("### Decrypted File")
                        st.download_button(
                            label=f"Download {filename}",
                            data=decrypted_data,
                            file_name=filename,
                            mime="application/octet-stream"
                        )
                    else:
                        # Handle text display
                        st.markdown("### Decrypted Text")
                        st.code(decrypted_data)
                else:
                    st.error("Failed to decrypt data. This should not happen if the passkey is correct.")
            else:
                # Increment failed attempts
                st.session_state.failed_attempts += 1
                
                if st.session_state.failed_attempts >= st.session_state.max_attempts:
                    st.session_state.is_authenticated = False
                    st.error(f"Maximum attempts ({st.session_state.max_attempts}) reached. You need to authenticate again.")
                    time.sleep(1)
                    navigate_to('login')
                else:
                    remaining = st.session_state.max_attempts - st.session_state.failed_attempts
                    st.error(f"Incorrect passkey! {remaining} attempts remaining.")
    
    # Delete data option
    with st.expander("Delete Data"):
        st.warning("⚠️ This action cannot be undone!")
        delete_key = st.selectbox("Select Data to Delete", data_keys, key="delete_select")
        delete_confirm = st.text_input("Type the data key to confirm deletion", placeholder=f"Type '{delete_key}' to confirm")
        
        if st.button("Delete Data", use_container_width=True):
            if delete_confirm == delete_key:
                del st.session_state.stored_data[delete_key]
                st.success(f"Data '{delete_key}' deleted successfully!")
                time.sleep(1)
                st.experimental_rerun()
            else:
                st.error("Confirmation text doesn't match the data key.")
    
    # Back button
    if st.button("Back to Home", use_container_width=True):
        navigate_to('home')

def login_page():
    """Simple login page for re-authentication"""
    st.markdown("<h1 class='main-header'>Authentication Required</h1>", unsafe_allow_html=True)
    st.markdown("<p class='sub-header'>Too many failed attempts. Please authenticate to continue.</p>", unsafe_allow_html=True)
    
    # Simple authentication mechanism
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    # For demonstration purposes, we'll use a simple username/password
    # In a real application, you would use a more secure authentication method
    if st.button("Authenticate", type="primary", use_container_width=True):
        if username == "admin" and password == "password":  # DEMO ONLY - use proper auth in production!
            st.session_state.is_authenticated = True
            st.session_state.failed_attempts = 0
            st.success("Authentication successful!")
            
            # Show a progress bar for visual feedback
            progress_bar = st.progress(0)
            for i in range(100):
                time.sleep(0.01)
                progress_bar.progress(i + 1)
            
            navigate_to('retrieve_data')
        else:
            st.error("Authentication failed. Please try again.")
    
    # Back button
    if st.button("Back to Home", use_container_width=True):
        navigate_to('home')

# Main app logic
def main():
    # Display the appropriate page based on the current_page state
    if st.session_state.current_page == 'home':
        home_page()
    elif st.session_state.current_page == 'insert_data':
        insert_data_page()
    elif st.session_state.current_page == 'retrieve_data':
        retrieve_data_page()
    elif st.session_state.current_page == 'login':
        login_page()

# Run the app
if __name__ == "__main__":
    main()