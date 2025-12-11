"""
Core encryption module for PassSafe CLI.
Handles AES-256-GCM encryption and PBKDF2 key derivation.
"""

import os
import json
import hashlib
from getpass import getpass
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class EncryptionError(Exception):
    """Raised when encryption/decryption operations fail."""
    pass


class CryptoCore:
    """
    Core cryptographic operations for PassSafe.
    
    Uses AES-256-GCM for encryption with PBKDF2-HMAC-SHA256 key derivation.
    """
    
    SALT_LENGTH = 32
    NONCE_LENGTH = 12
    KEY_LENGTH = 32
    PBKDF2_ITERATIONS = 200_000
    
    def __init__(self):
        self.backend = default_backend()
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: Master password
            salt: Random salt for key derivation
            
        Returns:
            32-byte encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt_data(self, data: str, password: str) -> bytes:
        """
        Encrypt data with AES-256-GCM.
        
        Args:
            data: JSON string to encrypt
            password: Master password
            
        Returns:
            Encrypted bytes with salt+nonce+tag+data
        """
        try:
            # Generate random salt and nonce
            salt = os.urandom(self.SALT_LENGTH)
            nonce = os.urandom(self.NONCE_LENGTH)
            
            # Derive key from password
            key = self.derive_key(password, salt)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            # Encrypt data
            ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
            
            # Combine salt + nonce + tag + ciphertext
            encrypted_data = salt + nonce + encryptor.tag + ciphertext
            
            return encrypted_data
            
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt data: {e}")
    
    def decrypt_data(self, encrypted_data: bytes, password: str) -> str:
        """
        Decrypt data with AES-256-GCM.
        
        Args:
            encrypted_data: Encrypted bytes with salt+nonce+tag+data
            password: Master password
            
        Returns:
            Decrypted JSON string
            
        Raises:
            EncryptionError: If decryption fails (wrong password or corrupted data)
        """
        try:
            # Extract components
            salt = encrypted_data[:self.SALT_LENGTH]
            nonce = encrypted_data[self.SALT_LENGTH:self.SALT_LENGTH + self.NONCE_LENGTH]
            tag = encrypted_data[self.SALT_LENGTH + self.NONCE_LENGTH:self.SALT_LENGTH + self.NONCE_LENGTH + 16]
            ciphertext = encrypted_data[self.SALT_LENGTH + self.NONCE_LENGTH + 16:]
            
            # Derive key from password
            key = self.derive_key(password, salt)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise EncryptionError(f"Failed to decrypt data: {e}")
    
    def verify_password(self, encrypted_data: bytes, password: str) -> bool:
        """
        Verify if password can decrypt the data.
        
        Args:
            encrypted_data: Encrypted vault data
            password: Master password to verify
            
        Returns:
            True if password is correct, False otherwise
        """
        try:
            self.decrypt_data(encrypted_data, password)
            return True
        except EncryptionError:
            return False
    
    def get_password_strength(self, password: str) -> dict:
        """
        Analyze password strength.
        
        Args:
            password: Password to analyze
            
        Returns:
            Dictionary with strength metrics
        """
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        
        # Calculate entropy score
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_symbol:
            charset_size += 32
        
        entropy = length * (charset_size.bit_length() if charset_size > 0 else 0)
        
        # Determine strength
        if length < 8:
            strength = "very_weak"
        elif length < 12 or entropy < 50:
            strength = "weak"
        elif length < 16 or entropy < 70:
            strength = "moderate"
        elif length < 20 or entropy < 90:
            strength = "strong"
        else:
            strength = "very_strong"
        
        return {
            "length": length,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_symbol": has_symbol,
            "entropy": entropy,
            "strength": strength
        }


def get_master_password(confirm: bool = False) -> str:
    """
    Securely get master password from user input.
    
    Args:
        confirm: If True, ask for password confirmation
        
    Returns:
        Master password string
        
    Raises:
        ValueError: If passwords don't match when confirmation is required
    """
    password = getpass("Enter master password: ")
    
    if confirm:
        confirm_password = getpass("Confirm master password: ")
        if password != confirm_password:
            raise ValueError("Passwords do not match")
    
    if not password:
        raise ValueError("Master password cannot be empty")
    
    return password


def hash_service_name(service: str) -> str:
    """
    Create a hash of service name for stealth mode.
    
    Args:
        service: Service name to hash
        
    Returns:
        Hashed service name
    """
    return hashlib.sha256(service.encode('utf-8')).hexdigest()[:16]