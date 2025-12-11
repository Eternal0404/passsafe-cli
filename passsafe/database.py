"""
Database module for PassSafe CLI.
Handles encrypted vault storage and operations.
"""

import os
import json
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any

from .core import CryptoCore, EncryptionError


class VaultError(Exception):
    """Raised when vault operations fail."""
    pass


class Vault:
    """
    Encrypted password vault database.
    
    Manages storage, retrieval, and encryption of password entries.
    """
    
    def __init__(self, vault_path: str = None):
        """
        Initialize vault.
        
        Args:
            vault_path: Path to vault file (default: data/vault.passsafe)
        """
        self.crypto = CryptoCore()
        self.vault_path = vault_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 
            "data", 
            "vault.passsafe"
        )
        self.data = None
        self.unlocked = False
        self.stealth_mode = False
    
    def exists(self) -> bool:
        """Check if vault file exists."""
        return os.path.exists(self.vault_path)
    
    def create(self, master_password: str) -> None:
        """
        Create new encrypted vault.
        
        Args:
            master_password: Master password for vault
            
        Raises:
            VaultError: If vault already exists or creation fails
        """
        if self.exists():
            raise VaultError("Vault already exists")
        
        try:
            # Initialize empty vault structure
            vault_data = {
                "version": "1.0.0",
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
                "items": [],
                "meta": {
                    "total_items": 0,
                    "categories": {},
                    "stealth_mode": False
                }
            }
            
            # Encrypt and save
            json_data = json.dumps(vault_data, indent=2)
            encrypted_data = self.crypto.encrypt_data(json_data, master_password)
            
            # Ensure data directory exists
            os.makedirs(os.path.dirname(self.vault_path), exist_ok=True)
            
            # Write encrypted vault
            with open(self.vault_path, 'wb') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            raise VaultError(f"Failed to create vault: {e}")
    
    def unlock(self, master_password: str) -> bool:
        """
        Unlock vault with master password.
        
        Args:
            master_password: Master password
            
        Returns:
            True if unlock successful, False otherwise
            
        Raises:
            VaultError: If vault doesn't exist or is corrupted
        """
        if not self.exists():
            raise VaultError("Vault does not exist")
        
        try:
            # Read encrypted vault
            with open(self.vault_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt vault data
            json_data = self.crypto.decrypt_data(encrypted_data, master_password)
            self.data = json.loads(json_data)
            self.unlocked = True
            self.stealth_mode = self.data["meta"].get("stealth_mode", False)
            
            return True
            
        except EncryptionError:
            return False
        except Exception as e:
            raise VaultError(f"Failed to unlock vault: {e}")
    
    def lock(self) -> None:
        """Lock vault (clear decrypted data from memory)."""
        self.data = None
        self.unlocked = False
        self.stealth_mode = False
    
    def save(self, master_password: str) -> None:
        """
        Save vault changes.
        
        Args:
            master_password: Master password for encryption
            
        Raises:
            VaultError: If vault is not unlocked or save fails
        """
        if not self.unlocked or not self.data:
            raise VaultError("Vault is not unlocked")
        
        try:
            # Update metadata
            self.data["updated_at"] = datetime.utcnow().isoformat()
            self.data["meta"]["total_items"] = len(self.data["items"])
            self.data["meta"]["stealth_mode"] = self.stealth_mode
            
            # Update category counts
            categories = {}
            for item in self.data["items"]:
                cat = item.get("category", "misc")
                categories[cat] = categories.get(cat, 0) + 1
            self.data["meta"]["categories"] = categories
            
            # Encrypt and save
            json_data = json.dumps(self.data, indent=2)
            encrypted_data = self.crypto.encrypt_data(json_data, master_password)
            
            with open(self.vault_path, 'wb') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            raise VaultError(f"Failed to save vault: {e}")
    
    def add_item(self, service: str, username: str, password: str, 
                 category: str = None, notes: str = None) -> str:
        """
        Add new password entry.
        
        Args:
            service: Service name
            username: Username/email
            password: Password
            category: Category (auto-detected if None)
            notes: Optional notes
            
        Returns:
            ID of created item
            
        Raises:
            VaultError: If vault is not unlocked
        """
        if not self.unlocked:
            raise VaultError("Vault is not unlocked")
        
        # Auto-detect category if not provided
        if category is None:
            from .categories import categorize_service
            category = categorize_service(service)
        
        # Create item
        item = {
            "id": self._generate_id(),
            "service": service,
            "username": username,
            "password": password,
            "category": category,
            "notes": notes or "",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        # Add to vault
        self.data["items"].append(item)
        return item["id"]
    
    def find_items(self, service: str) -> List[Dict]:
        """
        Find items by service name (case-insensitive).
        
        Args:
            service: Service name to search for
            
        Returns:
            List of matching items
            
        Raises:
            VaultError: If vault is not unlocked
        """
        if not self.unlocked:
            raise VaultError("Vault is not unlocked")
        
        service_lower = service.lower()
        matches = []
        
        for item in self.data["items"]:
            if service_lower in item["service"].lower():
                # Apply stealth mode if enabled
                if self.stealth_mode:
                    from .core import hash_service_name
                    item_copy = item.copy()
                    item_copy["service"] = hash_service_name(item["service"])
                    matches.append(item_copy)
                else:
                    matches.append(item)
        
        return matches
    
    def get_item(self, item_id: str) -> Optional[Dict]:
        """
        Get item by ID.
        
        Args:
            item_id: Item ID
            
        Returns:
            Item dictionary or None if not found
            
        Raises:
            VaultError: If vault is not unlocked
        """
        if not self.unlocked:
            raise VaultError("Vault is not unlocked")
        
        for item in self.data["items"]:
            if item["id"] == item_id:
                return item
        
        return None
    
    def update_item(self, item_id: str, **kwargs) -> bool:
        """
        Update item fields.
        
        Args:
            item_id: Item ID
            **kwargs: Fields to update
            
        Returns:
            True if updated, False if not found
            
        Raises:
            VaultError: If vault is not unlocked
        """
        if not self.unlocked:
            raise VaultError("Vault is not unlocked")
        
        for item in self.data["items"]:
            if item["id"] == item_id:
                # Update fields
                for key, value in kwargs.items():
                    if key in item:
                        item[key] = value
                
                item["updated_at"] = datetime.utcnow().isoformat()
                return True
        
        return False
    
    def delete_item(self, item_id: str) -> bool:
        """
        Delete item by ID.
        
        Args:
            item_id: Item ID
            
        Returns:
            True if deleted, False if not found
            
        Raises:
            VaultError: If vault is not unlocked
        """
        if not self.unlocked:
            raise VaultError("Vault is not unlocked")
        
        for i, item in enumerate(self.data["items"]):
            if item["id"] == item_id:
                del self.data["items"][i]
                return True
        
        return False
    
    def get_all_items(self) -> List[Dict]:
        """
        Get all items in vault.
        
        Returns:
            List of all items (with stealth mode applied if enabled)
            
        Raises:
            VaultError: If vault is not unlocked
        """
        if not self.unlocked:
            raise VaultError("Vault is not unlocked")
        
        items = self.data["items"].copy()
        
        # Apply stealth mode if enabled
        if self.stealth_mode:
            from .core import hash_service_name
            for item in items:
                item["service"] = hash_service_name(item["service"])
        
        return items
    
    def backup(self, backup_path: str = None) -> str:
        """
        Create encrypted backup of vault.
        
        Args:
            backup_path: Custom backup path
            
        Returns:
            Path to backup file
            
        Raises:
            VaultError: If vault is not unlocked or backup fails
        """
        if not self.unlocked:
            raise VaultError("Vault is not unlocked")
        
        if backup_path is None:
            timestamp = datetime.now().strftime("%Y-%m-%d")
            backup_dir = os.path.dirname(self.vault_path)
            backup_path = os.path.join(backup_dir, f"backup_{timestamp}.passsafe")
        
        try:
            shutil.copy2(self.vault_path, backup_path)
            return backup_path
        except Exception as e:
            raise VaultError(f"Failed to create backup: {e}")
    
    def restore(self, backup_path: str, master_password: str) -> None:
        """
        Restore vault from backup.
        
        Args:
            backup_path: Path to backup file
            master_password: Master password
            
        Raises:
            VaultError: If restore fails
        """
        try:
            # Verify backup can be decrypted
            with open(backup_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Test decryption
            self.crypto.decrypt_data(encrypted_data, master_password)
            
            # Replace current vault
            shutil.copy2(backup_path, self.vault_path)
            
            # Lock and unlock to refresh data
            self.lock()
            self.unlock(master_password)
            
        except Exception as e:
            raise VaultError(f"Failed to restore backup: {e}")
    
    def set_stealth_mode(self, enabled: bool) -> None:
        """
        Enable or disable stealth mode.
        
        Args:
            enabled: Whether to enable stealth mode
        """
        self.stealth_mode = enabled
        if self.data:
            self.data["meta"]["stealth_mode"] = enabled
    
    def _generate_id(self) -> str:
        """Generate unique item ID."""
        import uuid
        return str(uuid.uuid4())
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get vault statistics.
        
        Returns:
            Dictionary with vault stats
            
        Raises:
            VaultError: If vault is not unlocked
        """
        if not self.unlocked:
            raise VaultError("Vault is not unlocked")
        
        items = self.data["items"]
        total = len(items)
        
        # Category breakdown
        categories = {}
        for item in items:
            cat = item.get("category", "misc")
            categories[cat] = categories.get(cat, 0) + 1
        
        # Age analysis
        now = datetime.utcnow()
        old_items = 0
        for item in items:
            updated = datetime.fromisoformat(item["updated_at"].replace('Z', '+00:00'))
            age_days = (now - updated).days
            if age_days > 90:
                old_items += 1
        
        return {
            "total_items": total,
            "categories": categories,
            "old_items": old_items,
            "stealth_mode": self.stealth_mode,
            "created_at": self.data["created_at"],
            "updated_at": self.data["updated_at"]
        }