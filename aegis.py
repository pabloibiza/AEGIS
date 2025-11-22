#!/usr/bin/env python3
"""
AEGIS - Triple Layer Encryption System
RSA-4096 + Double Layer AES (AES-256-GCM + AES-256-EAX)

STRUCTURE:
- file.enc    → Encrypted data (double layer: AES-256-GCM + AES-256-EAX)
- file.keys   → Symmetric keys encrypted with RSA-4096
- file.rsakey → RSA-4096 private key

FEATURES:
- Files of any size (chunk reading)
- Unique keys per file (AES-256 + AES-256 + RSA-4096)
- Original name preserved in .enc
"""

import os
import sys
import platform
import shutil
import argparse
from pathlib import Path
from typing import Tuple, Optional
import time

# Detect OS and add appropriate lib folder to path
_script_dir = os.path.dirname(os.path.abspath(__file__))
_system = platform.system().lower()

# Select lib folder based on OS
if _system == 'windows':
    _lib_path = os.path.join(_script_dir, 'lib')
elif _system == 'linux':
    _lib_path = os.path.join(_script_dir, 'lib_linux')
elif _system == 'darwin':  # macOS
    _lib_path = os.path.join(_script_dir, 'lib_macos')
else:
    _lib_path = None

# Add lib folder to path if exists
if _lib_path and os.path.exists(_lib_path) and _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

# Try to import PyCryptodome, install if missing
try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
except (ImportError, OSError) as e:
    print("\n" + "="*70)
    print("PyCryptodome not found or incompatible with your system.")
    print("="*70)
    print("\nInstalling PyCryptodome automatically...\n")
    
    import subprocess
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "pycryptodome"])
        print("\n" + "="*70)
        print("Installation successful! Please run the command again.")
        print("="*70 + "\n")
        sys.exit(0)
    except subprocess.CalledProcessError:
        print("\n" + "="*70)
        print("ERROR: Automatic installation failed.")
        print("="*70)
        print("\nPlease install manually:")
        print("  pip install pycryptodome")
        print("\nOr:")
        print("  python -m pip install pycryptodome")
        print("="*70 + "\n")
        sys.exit(1)




# ============================================================================
# CONSTANTS
# ============================================================================
VERSION = "Aegis 1.0"

RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 32  # 256 bits (inner layer - GCM)
AES_EAX_KEY_SIZE = 32  # 256 bits (outer layer - EAX)
CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB chunks for large files

EXTENSION_ENC = ".enc"
EXTENSION_KEYS = ".keys"
EXTENSION_RSAKEY = ".rsakey"

# Magic markers to identify file type
MAGIC_ENC = b"AEGISENC"
MAGIC_KEYS = b"AEGISKEY"
MAGIC_RSA = b"-----BEGIN RSA PRIVATE KEY-----"


# ============================================================================
# RSA KEY GENERATION
# ============================================================================

def generate_rsa_keypair():
    """
    Generates a unique RSA-4096 key pair

    Returns:
        (private_key, public_key) RSA objects
    """
    print("[*] Generating unique RSA-4096 key pair...")
    
    key = RSA.generate(RSA_KEY_SIZE)
    
    print("[OK] RSA-4096 keys generated")
    
    return key


def save_private_key(key, filepath: str):
    """Saves RSA private key to PEM file"""
    with open(filepath, 'wb') as f:
        f.write(key.export_key('PEM'))


def load_private_key(filepath: str):
    """Loads RSA private key from PEM file"""
    with open(filepath, 'rb') as f:
        return RSA.import_key(f.read())


# ============================================================================
# ENCRYPTION AND DECRYPTION FUNCTIONS
# ============================================================================

def encrypt_file(input_path: str, output_base: Optional[str] = None, cancel_callback=None) -> bool:
    """
    Encrypts file:

    OUTPUT:
    1. file.enc   → Encrypted data (double layer AES-GCM + AES-EAX)
    2. file.keys  → Symmetric keys (encrypted with RSA)
    3. file.rsakey → RSA private key

    OUTPUT NAME:
    - document.pdf → document.enc
    - photo.jpg → photo.enc
    """
    try:
        print(f"\n{'='*70}")
        print(f"  ENCRYPTING: {os.path.basename(input_path)}")
        print(f"{'='*70}\n")
        
        # Get file size without loading into memory
        file_size = os.path.getsize(input_path)
        print(f"[*] File size: {file_size:,} bytes")
        
        # Calculate chunks for progress reporting
        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        if total_chunks > 1:
            print(f"[*] Processing in {total_chunks} chunks of {CHUNK_SIZE // (1024*1024)} MB\n")
        else:
            print()
        
        # Get original file name (with extension)
        original_filename = os.path.basename(input_path).encode('utf-8')
        
        # Determine base output name (WITHOUT original extension)
        if output_base is None:
            # Remove the extension from the original file
            base_name = os.path.splitext(input_path)[0]
            output_base = base_name
        
        print(f"[*] Output base name: {os.path.basename(output_base)}")
        print(f"[*] Original name saved: {original_filename.decode('utf-8')}\n")
        
        # Generate UNIQUE RSA-4096 key pair 
        print("[STEP 1] Generating UNIQUE RSA-4096 keys for this file")
        rsa_key = generate_rsa_keypair()
        
        # Save RSA private key
        rsakey_path = output_base + EXTENSION_RSAKEY
        save_private_key(rsa_key, rsakey_path)
        print(f"[OK] RSA private key: {rsakey_path}")
        print(f"[!] IMPORTANT: Save this file securely!\n")
        
        # Generate unique symmetric keys
        print("[STEP 2] Generating UNIQUE symmetric keys")
        aes_key = get_random_bytes(AES_KEY_SIZE)
        aes_eax_key = get_random_bytes(AES_EAX_KEY_SIZE)
        print(f"[*] AES-256-GCM key (layer 1): {aes_key[:8].hex()}... (unique)")
        print(f"[*] AES-256-EAX key (layer 2): {aes_eax_key[:8].hex()}... (unique)\n")
        
        # INNER LAYER - AES-256-GCM (streaming)
        print("[STEP 3] Inner layer: Encrypting with AES-256-GCM...")
        cipher_gcm = AES.new(aes_key, AES.MODE_GCM)
        aes_nonce = cipher_gcm.nonce
        
        # Create temporary file for GCM encrypted data
        import tempfile
        temp_gcm = tempfile.NamedTemporaryFile(delete=False, suffix='.tmp')
        temp_gcm_path = temp_gcm.name
        
        try:
            with open(input_path, 'rb') as f_in:
                bytes_processed = 0
                start_time = time.time()
                
                while True:
                    # Check for cancellation
                    if cancel_callback and cancel_callback():
                        print("\n[!] Operation cancelled by user")
                        if os.path.exists(temp_gcm_path):
                            os.unlink(temp_gcm_path)
                        return False
                    
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    encrypted_chunk = cipher_gcm.encrypt(chunk)
                    temp_gcm.write(encrypted_chunk)
                    
                    bytes_processed += len(chunk)
                    if total_chunks > 1:
                        show_progress_bar(bytes_processed, file_size, 
                                        prefix='[*] AES-GCM', 
                                        suffix='Complete', 
                                        start_time=start_time)
            
            if total_chunks <= 1:
                print()  # New line for small files
            
            aes_tag = cipher_gcm.digest()
            temp_gcm.close()
            
            gcm_size = os.path.getsize(temp_gcm_path)
            print(f"[OK] Data encrypted with AES-256-GCM")
            print(f"[*] AES encrypted size: {gcm_size:,} bytes\n")
            
            # OUTER LAYER - AES-256-EAX (streaming)
            print("[STEP 4] Outer layer: Encrypting with AES-256-EAX...")
            cipher_eax = AES.new(aes_eax_key, AES.MODE_EAX)
            eax_nonce = cipher_eax.nonce
            
            # Create temporary file for EAX encrypted data
            temp_eax = tempfile.NamedTemporaryFile(delete=False, suffix='.tmp')
            temp_eax_path = temp_eax.name
            
            with open(temp_gcm_path, 'rb') as f_in:
                bytes_processed = 0
                start_time = time.time()
                
                while True:
                    # Check for cancellation
                    if cancel_callback and cancel_callback():
                        print("\n[!] Operation cancelled by user")
                        if os.path.exists(temp_gcm_path):
                            os.unlink(temp_gcm_path)
                        if os.path.exists(temp_eax_path):
                            os.unlink(temp_eax_path)
                        return False
                    
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    encrypted_chunk = cipher_eax.encrypt(chunk)
                    temp_eax.write(encrypted_chunk)
                    
                    bytes_processed += len(chunk)
                    if total_chunks > 1:
                        show_progress_bar(bytes_processed, gcm_size, 
                                        prefix='[*] AES-EAX', 
                                        suffix='Complete', 
                                        start_time=start_time)
            
            if total_chunks <= 1:
                print()  # New line for small files
            
            eax_tag = cipher_eax.digest()
            temp_eax.close()
            
            eax_size = os.path.getsize(temp_eax_path)
            print(f"[OK] Data encrypted with AES-256-EAX (layer 2)")
            print(f"[*] Final encrypted size: {eax_size:,} bytes\n")
        
        except Exception as e:
            # Clean up temp files on error
            if os.path.exists(temp_gcm_path):
                os.unlink(temp_gcm_path)
            raise e
        
        # Save .ENC FILE (encrypted data)
        print("[STEP 5] Creating .enc file with encrypted data...")
        enc_path = output_base + EXTENSION_ENC
        
        try:
            with open(enc_path, 'wb') as f:
                # Magic header for identification
                f.write(MAGIC_ENC)
                f.write(len(original_filename).to_bytes(4, 'little'))
                f.write(original_filename)
                
                # AES-EAX metadata (outer layer)
                f.write(len(eax_nonce).to_bytes(4, 'little'))
                f.write(eax_nonce)
                f.write(len(eax_tag).to_bytes(4, 'little'))
                f.write(eax_tag)
                
                # AES-GCM metadata (inner layer)
                f.write(len(aes_nonce).to_bytes(4, 'little'))
                f.write(aes_nonce)
                f.write(len(aes_tag).to_bytes(4, 'little'))
                f.write(aes_tag)
                
                # Encrypted data (outer layer AES-EAX) - stream from temp file
                with open(temp_eax_path, 'rb') as f_temp:
                    while True:
                        chunk = f_temp.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        f.write(chunk)
            
            print(f"[OK] .enc file created: {enc_path}\n")
        
        finally:
            # Clean up temporary files
            if os.path.exists(temp_gcm_path):
                os.unlink(temp_gcm_path)
            if os.path.exists(temp_eax_path):
                os.unlink(temp_eax_path)
        
        # Encrypt symmetric keys with RSA
        print("[STEP 6] Protecting symmetric keys with RSA-4096...")
        
        # Combine symmetric keys into one block
        keys_block = aes_key + aes_eax_key  # 64 bytes total (32 + 32)
        
        # Encrypt block with RSA
        cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey(), hashAlgo=SHA256)
        encrypted_keys = cipher_rsa.encrypt(keys_block)
        
        print(f"[OK] Symmetric keys protected with RSA-4096\n")
        
        # Save .KEYS FILE (encrypted keys)
        print("[STEP 7] Creating .keys file with encrypted keys...")
        keys_path = output_base + EXTENSION_KEYS
        with open(keys_path, 'wb') as f:
            f.write(MAGIC_KEYS)  # Magic marker for identification
            f.write(len(encrypted_keys).to_bytes(4, 'little'))
            f.write(encrypted_keys)
        
        print(f"[OK] .keys file created: {keys_path}\n")
        
        # SUMMARY
        enc_size = os.path.getsize(enc_path)
        keys_size = os.path.getsize(keys_path)
        rsakey_size = os.path.getsize(rsakey_path)
        
        print(f"{'='*70}")
        print(f"  ENCRYPTION COMPLETED")
        print(f"{'='*70}")

        print(f"\n[OK] Generated files:\n")
        print(f"  1. {os.path.basename(enc_path)}")
        print(f"     - Encrypted data (double layer AES-256-GCM + AES-256-EAX)")
        print(f"     - Size: {enc_size:,} bytes\n")
        
        print(f"  2. {os.path.basename(keys_path)}")
        print(f"     - AES symmetric keys (encrypted with RSA-4096)")
        print(f"     - Size: {keys_size:,} bytes\n")
        
        print(f"  3. {os.path.basename(rsakey_path)}")
        print(f"     - Unique RSA-4096 private key")
        print(f"     - Size: {rsakey_size:,} bytes\n")
        
        print(f"[!] IMPORTANT:")
        print(f"    - Save {os.path.basename(rsakey_path)} in a SECURE location")
        print(f"    - Without it, you CANNOT decrypt this file")
        print(f"    - Backup all 3 files\n")
        
        print(f"{'='*70}\n")
        
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Encryption failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def identify_file_type(filepath: str) -> str:
    """
    Identifies the file type by its content (magic bytes)

    Returns:
        'enc', 'keys', 'rsakey', or 'unknown'
    """
    try:
        with open(filepath, 'rb') as f:
            header = f.read(64)
        
        if header.startswith(MAGIC_ENC):
            return 'enc'
        elif header.startswith(MAGIC_KEYS):
            return 'keys'
        elif header.startswith(MAGIC_RSA) or b"BEGIN RSA PRIVATE KEY" in header:
            return 'rsakey'
        else:
            return 'unknown'
    except:
        return 'unknown'


def decrypt_file(enc_path: str, keys_path: str, rsakey_path: str,
                output_path: Optional[str] = None, cancel_callback=None) -> bool:
    """
    Decrypts file:

    INPUT (in any order):
    1. file.enc   → Encrypted data
    2. file.keys  → Symmetric keys encrypted
    3. file.rsakey → RSA private key
    """
    try:
        print(f"\n{'='*70}")
        print(f"  DECRYPTING: {os.path.basename(enc_path)}")
        print(f"{'='*70}\n")
        
        # Load RSA private key
        print(f"[STEP 1] Loading RSA private key from: {rsakey_path}")
        rsa_key = load_private_key(rsakey_path)
        print("[OK] RSA private key loaded\n")
        
        # Decrypt .KEYS FILE
        print(f"[STEP 2] Decrypting .keys file with RSA-4096...")
        
        with open(keys_path, 'rb') as f:
            magic = f.read(8)
            if magic != MAGIC_KEYS:
                print(f"[ERROR] Invalid or incorrect version .keys file")
                return False
            
            encrypted_keys_len = int.from_bytes(f.read(4), 'little')
            encrypted_keys = f.read(encrypted_keys_len)
        
        # Decrypt symmetric keys with RSA
        cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        keys_block = cipher_rsa.decrypt(encrypted_keys)
        
        # Extract keys
        aes_key = keys_block[0:32]
        aes_eax_key = keys_block[32:64]
        
        print(f"[OK] Symmetric keys recovered")
        print(f"[*] AES-GCM key: {aes_key[:8].hex()}...")
        print(f"[*] AES-EAX key: {aes_eax_key[:8].hex()}...\n")
        
        # Read .ENC FILE
        print(f"[STEP 3] Reading .enc file...")
        
        with open(enc_path, 'rb') as f:
            magic = f.read(8)
            if magic != MAGIC_ENC:
                print(f"[ERROR] Invalid or incorrect version .enc file")
                return False
            
            # Read original file name
            filename_len = int.from_bytes(f.read(4), 'little')
            original_filename = f.read(filename_len).decode('utf-8')
            print(f"[*] Original file: {original_filename}")
            
            # Read AES-EAX metadata (outer layer)
            eax_nonce_len = int.from_bytes(f.read(4), 'little')
            eax_nonce = f.read(eax_nonce_len)
            eax_tag_len = int.from_bytes(f.read(4), 'little')
            eax_tag = f.read(eax_tag_len)
            
            # Read AES-GCM metadata (inner layer)
            aes_nonce_len = int.from_bytes(f.read(4), 'little')
            aes_nonce = f.read(aes_nonce_len)
            aes_tag_len = int.from_bytes(f.read(4), 'little')
            aes_tag = f.read(aes_tag_len)
            
            # Read encrypted data (double layer)
            eax_ciphertext = f.read()
        
        print(f"[OK] Encrypted data read: {len(eax_ciphertext):,} bytes\n")
        
        # Calculate chunks for progress
        encrypted_size = len(eax_ciphertext)
        total_chunks = (encrypted_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        if total_chunks > 1:
            print(f"[*] Processing in {total_chunks} chunks\n")
        
        # OUTER LAYER - Decrypt AES-256-EAX (streaming)
        print("[STEP 4] Decrypting outer layer: AES-256-EAX...")
        
        try:
            cipher_eax = AES.new(aes_eax_key, AES.MODE_EAX, nonce=eax_nonce)
            
            # Create temporary file for decrypted GCM layer
            import tempfile
            temp_gcm = tempfile.NamedTemporaryFile(delete=False, suffix='.tmp')
            temp_gcm_path = temp_gcm.name
            
            # Process in chunks
            offset = 0
            start_time = time.time()
            
            while offset < encrypted_size:
                # Check for cancellation
                if cancel_callback and cancel_callback():
                    print("\n[!] Operation cancelled by user")
                    if os.path.exists(temp_gcm_path):
                        os.unlink(temp_gcm_path)
                    return False
                
                chunk_size = min(CHUNK_SIZE, encrypted_size - offset)
                chunk = eax_ciphertext[offset:offset + chunk_size]
                
                decrypted_chunk = cipher_eax.decrypt(chunk)
                temp_gcm.write(decrypted_chunk)
                offset += chunk_size
                
                if total_chunks > 1:
                    show_progress_bar(offset, encrypted_size, 
                                    prefix='[*] AES-EAX', 
                                    suffix='Complete', 
                                    start_time=start_time)
            
            if total_chunks <= 1:
                print()  # New line for small files
            
            # Verify authentication tag
            cipher_eax.verify(eax_tag)
            temp_gcm.close()
            
            gcm_size = os.path.getsize(temp_gcm_path)
            print(f"[OK] AES-256-EAX layer removed")
            print(f"[*] Internal data recovered: {gcm_size:,} bytes\n")
            
        except (ValueError, KeyError) as e:
            print(f"[ERROR] AES-EAX authentication failed - file modified")
            if os.path.exists(temp_gcm_path):
                os.unlink(temp_gcm_path)
            return False
        
        # INNER LAYER - Decrypt AES-256-GCM (streaming)
        print("[STEP 5] Decrypting inner layer: AES-256-GCM...")
        
        try:
            cipher_gcm = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
            
            # Create temporary file for final plaintext
            temp_plain = tempfile.NamedTemporaryFile(delete=False, suffix='.tmp')
            temp_plain_path = temp_plain.name
            
            with open(temp_gcm_path, 'rb') as f_in:
                bytes_processed = 0
                start_time = time.time()
                
                while True:
                    # Check for cancellation
                    if cancel_callback and cancel_callback():
                        print("\n[!] Operation cancelled by user")
                        if os.path.exists(temp_gcm_path):
                            os.unlink(temp_gcm_path)
                        if os.path.exists(temp_plain_path):
                            os.unlink(temp_plain_path)
                        return False
                    
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    decrypted_chunk = cipher_gcm.decrypt(chunk)
                    temp_plain.write(decrypted_chunk)
                    
                    bytes_processed += len(chunk)
                    if total_chunks > 1:
                        show_progress_bar(bytes_processed, gcm_size, 
                                        prefix='[*] AES-GCM', 
                                        suffix='Complete', 
                                        start_time=start_time)
            
            if total_chunks <= 1:
                print()  # New line for small files
            
            # Verify authentication tag
            cipher_gcm.verify(aes_tag)
            temp_plain.close()
            
            plaintext_size = os.path.getsize(temp_plain_path)
            print(f"[OK] AES-256-GCM layer removed")
            print(f"[*] Original data recovered: {plaintext_size:,} bytes\n")
            
        except (ValueError, KeyError) as e:
            print(f"[ERROR] AES authentication failed - file modified")
            if os.path.exists(temp_gcm_path):
                os.unlink(temp_gcm_path)
            if os.path.exists(temp_plain_path):
                os.unlink(temp_plain_path)
            return False
        
        # Save decrypted file
        if not output_path:
            output_dir = os.path.dirname(enc_path)
            output_path = os.path.join(output_dir, original_filename)
        
        print(f"[STEP 6] Saving decrypted file...")
        
        try:
            # Move temp file to final destination
            shutil.move(temp_plain_path, output_path)
            
            final_size = os.path.getsize(output_path)
            
            print(f"\n{'='*70}")
            print(f"  DECRYPTION COMPLETED")
            print(f"{'='*70}")
            print(f"\n[OK] Decrypted file: {output_path}")
            print(f"[OK] Size: {final_size:,} bytes")
            print(f"{'='*70}\n")
        
        finally:
            # Clean up temporary files
            if os.path.exists(temp_gcm_path):
                os.unlink(temp_gcm_path)
            if os.path.exists(temp_plain_path):
                os.unlink(temp_plain_path)
        
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================================
# PROGRESS BAR
# ============================================================================

def show_progress_bar(current: int, total: int, prefix: str = '', suffix: str = '', 
                     length: int = 50, fill: str = '█', start_time: float = None):
    """
    Display a progress bar in the console
    
    Args:
        current: Current progress value
        total: Total value
        prefix: Text before the progress bar
        suffix: Text after the progress bar
        length: Length of the progress bar
        fill: Fill character for the bar
        start_time: Start time for speed calculation
    """
    percent = 100 * (current / float(total))
    filled_length = int(length * current // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    
    # Calculate speed and ETA
    speed_info = ''
    if start_time and current > 0:
        elapsed = time.time() - start_time
        if elapsed > 0:
            speed = current / elapsed  # bytes per second
            if speed > 1024 * 1024:  # MB/s
                speed_info = f' | {speed / (1024 * 1024):.1f} MB/s'
            elif speed > 1024:  # KB/s
                speed_info = f' | {speed / 1024:.1f} KB/s'
            
            # Calculate ETA
            if current < total:
                remaining = total - current
                eta_seconds = remaining / speed
                if eta_seconds < 60:
                    speed_info += f' | ETA: {int(eta_seconds)}s'
                elif eta_seconds < 3600:
                    speed_info += f' | ETA: {int(eta_seconds / 60)}m {int(eta_seconds % 60)}s'
                else:
                    hours = int(eta_seconds / 3600)
                    minutes = int((eta_seconds % 3600) / 60)
                    speed_info += f' | ETA: {hours}h {minutes}m'
    
    print(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}{speed_info}', end='', flush=True)
    
    if current == total:
        print()  # New line when complete


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Aegis - Triple Layer Encryption with AES-256-GCM + AES-256-EAX and RSA-4096 Key Protection\n\n',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples of use:

  # Encrypt file
  python aegis.py -e document.pdf

    Generates:
        document.enc     - Encrypted data (double layer AES-256-GCM + AES-256-EAX)
        document.keys    - Symmetric keys (encrypted with RSA-4096)
        document.rsakey  - RSA-4096 private key

  # Decrypt file
  python aegis.py -d document.enc document.keys document.rsakey

    # Or using flags
  python aegis.py -d document.enc -k document.keys -r document.rsakey
"""
    )
    
    # Operations
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-e', '--encrypt', metavar='FILE', 
                      help='Encrypt file')
    group.add_argument('-d', '--decrypt', metavar='FILE', 
                      help='Decrypt file (.enc)')
    
    # Options
    parser.add_argument('-k', '--keys', metavar='KEYS_FILE',
                       help='Keys file (.keys)')
    parser.add_argument('-r', '--rsakey', metavar='RSA_FILE',
                       help='RSA private key file (.rsakey)')
    parser.add_argument('-o', '--output', metavar='FILE',
                       help='Output file (optional)')
    parser.add_argument('--version', action='version', version=VERSION)
    
    # Positional files (for decryption without order)
    parser.add_argument('files', nargs='*', help='Files (.enc, .keys, .rsakey in any order)')
    
    args = parser.parse_args()
    
    # Banner
    print("\n" + "="*70)
    print("  AEGIS - Triple Layer Encryption System")
    print("  RSA-4096 + Double Layer AES (AES-256-GCM + AES-256-EAX)")
    print("="*70 + "\n")
    
    # MODE 1: Encrypt with -e
    if args.encrypt:
        input_file = args.encrypt
        
        if not os.path.exists(input_file):
            print(f"\n[ERROR] File not found: {input_file}")
            return 1
        
        # Encrypt (generates 3 files)
        success = encrypt_file(input_file, args.output)
        return 0 if success else 1
    
    # MODE 2: Decrypt with -d (with or without -k and -r)
    elif args.decrypt:
        enc_file = args.decrypt
        
        if not os.path.exists(enc_file):
            print(f"\n[ERROR] File not found: {enc_file}")
            return 1
        
        # Automatically find files if not specified
        if not args.keys or not args.rsakey:
            base_name = os.path.splitext(enc_file)[0]
            
            if not args.keys:
                auto_keys = base_name + EXTENSION_KEYS
                if os.path.exists(auto_keys):
                    keys_file = auto_keys
                    print(f"\n[*] Automatically detected: {keys_file}")
                else:
                    print(f"\n[ERROR] {auto_keys} not found")
                    return 1
            else:
                keys_file = args.keys
            
            if not args.rsakey:
                auto_rsakey = base_name + EXTENSION_RSAKEY
                if os.path.exists(auto_rsakey):
                    rsakey_file = auto_rsakey
                    print(f"[*] Automatically detected: {rsakey_file}")
                else:
                    print(f"[ERROR] {auto_rsakey} not found")
                    return 1
            else:
                rsakey_file = args.rsakey
        else:
            keys_file = args.keys
            rsakey_file = args.rsakey
        
        # Decrypt
        success = decrypt_file(enc_file, keys_file, rsakey_file, args.output)
        return 0 if success else 1
    
    # MODE 3: Positional files
    elif args.files:
        if len(args.files) != 3:
            print(f"\n[ERROR] Exactly 3 files are required")
            print(f"Usage: python aegis.py file1 file2 file3")
            print(f"(Files can be in any order)")
            return 1
        
        print(f"\n[*] Detecting file types...")
        
        # Identify each file
        enc_file = None
        keys_file = None
        rsakey_file = None
        
        for filepath in args.files:
            if not os.path.exists(filepath):
                print(f"[ERROR] File not found: {filepath}")
                return 1
            
            file_type = identify_file_type(filepath)
            
            if file_type == 'enc':
                enc_file = filepath
                print(f"[OK] .enc detected: {filepath}")
            elif file_type == 'keys':
                keys_file = filepath
                print(f"[OK] .keys detected: {filepath}")
            elif file_type == 'rsakey':
                rsakey_file = filepath
                print(f"[OK] .rsakey detected: {filepath}")
            else:
                print(f"[ERROR] Unknown file type: {filepath}")
                return 1
        
        # Check that we have all 3 files
        if not enc_file or not keys_file or not rsakey_file:
            print(f"\n[ERROR] Missing files:")
            if not enc_file: print(f"  - .enc file")
            if not keys_file: print(f"  - .keys file")
            if not rsakey_file: print(f"  - .rsakey file")
            return 1
        
        # Decrypt
        success = decrypt_file(enc_file, keys_file, rsakey_file, args.output)
        return 0 if success else 1
    
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
