"""
Secure password generator module for PassSafe CLI.
Uses cryptographically secure random number generation.
"""

import secrets
import string
from typing import Optional


class PasswordGenerator:
    """
    Cryptographically secure password generator.
    
    Uses Python's secrets module for maximum security.
    """
    
    def __init__(self):
        """Initialize password generator."""
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def generate_password(self, length: int = 16, 
                         include_symbols: bool = True,
                         include_digits: bool = True,
                         include_uppercase: bool = True,
                         include_lowercase: bool = True,
                         uppercase_only: bool = False) -> str:
        """
        Generate a secure random password.
        
        Args:
            length: Password length (default: 16)
            include_symbols: Include special characters (default: True)
            include_digits: Include digits (default: True)
            include_uppercase: Include uppercase letters (default: True)
            include_lowercase: Include lowercase letters (default: True)
            uppercase_only: Use only uppercase letters (overrides other options)
            
        Returns:
            Generated password string
            
        Raises:
            ValueError: If no character sets are selected or length is too small
        """
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
        
        # Build character pool
        char_pool = ""
        
        if uppercase_only:
            char_pool = self.uppercase
        else:
            if include_lowercase:
                char_pool += self.lowercase
            if include_uppercase:
                char_pool += self.uppercase
            if include_digits:
                char_pool += self.digits
            if include_symbols:
                char_pool += self.symbols
        
        if not char_pool:
            raise ValueError("At least one character set must be selected")
        
        # Generate password
        password = ''.join(secrets.choice(char_pool) for _ in range(length))
        
        # Ensure password contains at least one character from each selected set
        if not uppercase_only:
            password = self._ensure_character_requirements(
                password, length, include_lowercase, include_uppercase,
                include_digits, include_symbols, char_pool
            )
        
        return password
    
    def _ensure_character_requirements(self, password: str, length: int,
                                      include_lowercase: bool,
                                      include_uppercase: bool,
                                      include_digits: bool,
                                      include_symbols: bool,
                                      char_pool: str) -> str:
        """
        Ensure password meets character requirements.
        
        Args:
            password: Generated password
            length: Desired length
            include_lowercase: Require lowercase
            include_uppercase: Require uppercase
            include_digits: Require digits
            include_symbols: Require symbols
            char_pool: Character pool for generation
            
        Returns:
            Password meeting all requirements
        """
        # Check requirements
        has_lower = any(c in self.lowercase for c in password)
        has_upper = any(c in self.uppercase for c in password)
        has_digit = any(c in self.digits for c in password)
        has_symbol = any(c in self.symbols for c in password)
        
        # If all requirements are met, return password
        requirements_met = True
        if include_lowercase and not has_lower:
            requirements_met = False
        if include_uppercase and not has_upper:
            requirements_met = False
        if include_digits and not has_digit:
            requirements_met = False
        if include_symbols and not has_symbol:
            requirements_met = False
        
        if requirements_met:
            return password
        
        # Regenerate if requirements not met
        return self.generate_password(
            length, include_symbols, include_digits,
            include_uppercase, include_lowercase, False
        )
    
    def generate_passphrase(self, word_count: int = 6, 
                           separator: str = "-",
                           capitalize: bool = False) -> str:
        """
        Generate a memorable passphrase.
        
        Args:
            word_count: Number of words (default: 6)
            separator: Word separator (default: "-")
            capitalize: Capitalize first letter of each word
            
        Returns:
            Generated passphrase
        """
        # Common words for passphrases (short, memorable words)
        word_list = [
            "apple", "banana", "orange", "grape", "lemon", "peach",
            "happy", "smile", "laugh", "joy", "fun", "play",
            "blue", "green", "red", "yellow", "purple", "orange",
            "cat", "dog", "bird", "fish", "bear", "lion",
            "run", "jump", "walk", "swim", "fly", "dance",
            "sun", "moon", "star", "cloud", "rain", "snow",
            "book", "pen", "paper", "desk", "chair", "door",
            "car", "bike", "train", "plane", "boat", "bus",
            "coffee", "tea", "water", "milk", "juice", "soda",
            "bread", "rice", "pasta", "soup", "salad", "fruit"
        ]
        
        words = []
        for _ in range(word_count):
            word = secrets.choice(word_list)
            if capitalize:
                word = word.capitalize()
            words.append(word)
        
        return separator.join(words)
    
    def check_password_strength(self, password: str) -> dict:
        """
        Analyze password strength.
        
        Args:
            password: Password to analyze
            
        Returns:
            Dictionary with strength analysis
        """
        length = len(password)
        has_lower = any(c in self.lowercase for c in password)
        has_upper = any(c in self.uppercase for c in password)
        has_digit = any(c in self.digits for c in password)
        has_symbol = any(c in self.symbols for c in password)
        
        # Calculate character set size
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_symbol:
            charset_size += len(self.symbols)
        
        # Calculate entropy
        if charset_size > 0:
            import math
            entropy = length * math.log2(charset_size)
        else:
            entropy = 0
        
        # Determine strength level
        if length < 8:
            strength = "very_weak"
            score = 1
        elif length < 12 or entropy < 50:
            strength = "weak"
            score = 2
        elif length < 16 or entropy < 70:
            strength = "moderate"
            score = 3
        elif length < 20 or entropy < 90:
            strength = "strong"
            score = 4
        else:
            strength = "very_strong"
            score = 5
        
        # Generate suggestions
        suggestions = []
        if length < 12:
            suggestions.append("Use at least 12 characters")
        if not has_lower:
            suggestions.append("Include lowercase letters")
        if not has_upper:
            suggestions.append("Include uppercase letters")
        if not has_digit:
            suggestions.append("Include numbers")
        if not has_symbol:
            suggestions.append("Include special characters")
        
        return {
            "length": length,
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_symbols": has_symbol,
            "charset_size": charset_size,
            "entropy": round(entropy, 2),
            "strength": strength,
            "score": score,
            "suggestions": suggestions
        }
    
    def generate_memorable_password(self, length: int = 12) -> str:
        """
        Generate a password that's easier to remember but still secure.
        
        Args:
            length: Password length
            
        Returns:
            Memorable password
        """
        # Start with a random word
        words = ["apple", "banana", "coffee", "dragon", "elephant", 
                "flower", "guitar", "house", "island", "jungle",
                "kitten", "lemon", "mountain", "number", "ocean",
                "piano", "queen", "river", "sunset", "tiger",
                "umbrella", "village", "window", "yellow", "zebra"]
        
        base_word = secrets.choice(words)
        remaining_length = length - len(base_word)
        
        if remaining_length <= 0:
            return base_word[:length]
        
        # Add random characters
        extra_chars = self.digits + self.symbols
        password = base_word.capitalize()
        
        for _ in range(remaining_length):
            password += secrets.choice(extra_chars)
        
        return password