"""
CLI interface for PassSafe CLI password manager.
Handles all command-line operations and user interaction.
"""

import argparse
import sys
import os
from getpass import getpass
from typing import Optional

from .core import get_master_password, VaultError, EncryptionError
from .database import Vault
from .generator import PasswordGenerator
from .analyzer import PasswordAnalyzer
from .categories import categorize_service, get_category_color


class PassSafeCLI:
    """
    Command-line interface for PassSafe password manager.
    """
    
    def __init__(self):
        """Initialize CLI."""
        self.vault = None
        self.generator = PasswordGenerator()
        self.analyzer = PasswordAnalyzer()
        self.master_password = None
    
    def run(self, args: Optional[list] = None) -> int:
        """
        Run the CLI application.
        
        Args:
            args: Command line arguments (for testing)
            
        Returns:
            Exit code
        """
        parser = self._create_parser()
        parsed_args = parser.parse_args(args)
        
        try:
            return self._execute_command(parsed_args)
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return 1
        except Exception as e:
            print(f"Error: {e}")
            return 1
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser."""
        parser = argparse.ArgumentParser(
            prog="passsafe",
            description="Secure local password manager with AES-256-GCM encryption"
        )
        
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        
        # Init command
        init_parser = subparsers.add_parser("init", help="Create new vault")
        
        # Unlock command
        unlock_parser = subparsers.add_parser("unlock", help="Unlock vault")
        
        # Add command
        add_parser = subparsers.add_parser("add", help="Add new password entry")
        add_parser.add_argument("service", help="Service name")
        add_parser.add_argument("username", help="Username or email")
        add_parser.add_argument("--category", help="Category (auto-detected if not provided)")
        add_parser.add_argument("--notes", help="Optional notes")
        add_parser.add_argument("--password", help="Password (will generate if not provided)")
        
        # Find command
        find_parser = subparsers.add_parser("find", help="Find password entries")
        find_parser.add_argument("service", help="Service name to search for")
        find_parser.add_argument("--reveal", action="store_true", help="Show passwords")
        
        # Analyze command
        analyze_parser = subparsers.add_parser("analyze", help="Analyze password security")
        
        # Backup command
        backup_parser = subparsers.add_parser("backup", help="Create encrypted backup")
        backup_parser.add_argument("--path", help="Custom backup path")
        
        # Restore command
        restore_parser = subparsers.add_parser("restore", help="Restore from backup")
        restore_parser.add_argument("file", help="Backup file path")
        
        # Stealth command
        stealth_parser = subparsers.add_parser("stealth", help="Toggle stealth mode")
        stealth_parser.add_argument("mode", choices=["on", "off"], help="Stealth mode")
        
        # Generate command
        gen_parser = subparsers.add_parser("generate", help="Generate secure password")
        gen_parser.add_argument("--len", type=int, default=16, help="Password length")
        gen_parser.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
        gen_parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
        gen_parser.add_argument("--uppercase-only", action="store_true", help="Uppercase only")
        gen_parser.add_argument("--no-lowercase", action="store_true", help="Exclude lowercase")
        
        # Status command
        status_parser = subparsers.add_parser("status", help="Show vault status")
        
        return parser
    
    def _execute_command(self, args) -> int:
        """Execute the specified command."""
        if args.command == "init":
            return self._cmd_init()
        elif args.command == "unlock":
            return self._cmd_unlock()
        elif args.command == "add":
            return self._cmd_add(args)
        elif args.command == "find":
            return self._cmd_find(args)
        elif args.command == "analyze":
            return self._cmd_analyze()
        elif args.command == "backup":
            return self._cmd_backup(args)
        elif args.command == "restore":
            return self._cmd_restore(args)
        elif args.command == "stealth":
            return self._cmd_stealth(args)
        elif args.command == "generate":
            return self._cmd_generate(args)
        elif args.command == "status":
            return self._cmd_status()
        else:
            print("Unknown command. Use --help for available commands.")
            return 1
    
    def _cmd_init(self) -> int:
        """Initialize new vault."""
        self.vault = Vault()
        
        if self.vault.exists():
            print("Vault already exists. Use 'restore' to recover or delete manually.")
            return 1
        
        try:
            master_password = get_master_password(confirm=True)
            self.vault.create(master_password)
            print("✅ Vault created successfully!")
            print(f"Location: {self.vault.vault_path}")
            return 0
        except Exception as e:
            print(f"Failed to create vault: {e}")
            return 1
    
    def _cmd_unlock(self) -> int:
        """Unlock vault."""
        self.vault = Vault()
        
        if not self.vault.exists():
            print("Vault does not exist. Use 'init' to create one.")
            return 1
        
        try:
            master_password = get_master_password()
            
            if self.vault.unlock(master_password):
                self.master_password = master_password
                print("✅ Vault unlocked successfully!")
                
                if self.vault.stealth_mode:
                    print("⚠️  Stealth mode is active")
                
                return 0
            else:
                print("❌ Invalid master password")
                return 1
        except Exception as e:
            print(f"Failed to unlock vault: {e}")
            return 1
    
    def _cmd_add(self, args) -> int:
        """Add new password entry."""
        if not self._ensure_unlocked():
            return 1
        
        try:
            # Get password
            if args.password:
                password = args.password
            else:
                generate = input("Generate secure password? (y/N): ").lower().startswith('y')
                if generate:
                    password = self.generator.generate_password()
                    print(f"Generated password: {password}")
                else:
                    password = getpass("Enter password: ")
            
            # Get category
            category = args.category
            if not category:
                category = categorize_service(args.service)
                print(f"Auto-detected category: {category}")
            
            # Add item
            item_id = self.vault.add_item(
                service=args.service,
                username=args.username,
                password=password,
                category=category,
                notes=args.notes
            )
            
            # Save vault
            self.vault.save(self.master_password)
            print(f"✅ Added {args.service} to vault")
            return 0
            
        except Exception as e:
            print(f"Failed to add entry: {e}")
            return 1
    
    def _cmd_find(self, args) -> int:
        """Find password entries."""
        if not self._ensure_unlocked():
            return 1
        
        try:
            items = self.vault.find_items(args.service)
            
            if not items:
                print(f"No entries found for '{args.service}'")
                return 0
            
            print(f"Found {len(items)} entr{'y' if len(items) == 1 else 'ies'}:")
            print()
            
            for item in items:
                self._print_item(item, args.reveal)
            
            return 0
            
        except Exception as e:
            print(f"Failed to find entries: {e}")
            return 1
    
    def _cmd_analyze(self) -> int:
        """Analyze password security."""
        if not self._ensure_unlocked():
            return 1
        
        try:
            items = self.vault.get_all_items()
            result = self.analyzer.analyze_vault(items)
            
            # Generate and print report
            report = self.analyzer.generate_report(result)
            print(report)
            
            # Print security score
            score = self.analyzer.get_security_score(result)
            print(f"\nSecurity Score: {score}/100")
            
            # Print recommendations
            recommendations = self.analyzer.get_recommendations(result)
            if recommendations:
                print("\nRecommendations:")
                for rec in recommendations:
                    print(f"  • {rec}")
            
            return 0
            
        except Exception as e:
            print(f"Failed to analyze vault: {e}")
            return 1
    
    def _cmd_backup(self, args) -> int:
        """Create encrypted backup."""
        if not self._ensure_unlocked():
            return 1
        
        try:
            backup_path = self.vault.backup(args.path)
            print(f"✅ Backup created: {backup_path}")
            return 0
        except Exception as e:
            print(f"Failed to create backup: {e}")
            return 1
    
    def _cmd_restore(self, args) -> int:
        """Restore from backup."""
        if not os.path.exists(args.file):
            print(f"Backup file not found: {args.file}")
            return 1
        
        try:
            master_password = get_master_password()
            
            # Create new vault instance for restore
            self.vault = Vault()
            self.vault.restore(args.file, master_password)
            
            print("✅ Vault restored from backup")
            return 0
        except Exception as e:
            print(f"Failed to restore backup: {e}")
            return 1
    
    def _cmd_stealth(self, args) -> int:
        """Toggle stealth mode."""
        if not self._ensure_unlocked():
            return 1
        
        try:
            enabled = args.mode == "on"
            self.vault.set_stealth_mode(enabled)
            self.vault.save(self.master_password)
            
            status = "enabled" if enabled else "disabled"
            print(f"✅ Stealth mode {status}")
            return 0
        except Exception as e:
            print(f"Failed to toggle stealth mode: {e}")
            return 1
    
    def _cmd_generate(self, args) -> int:
        """Generate secure password."""
        try:
            password = self.generator.generate_password(
                length=args.len,
                include_symbols=not args.no_symbols,
                include_digits=not args.no_digits,
                include_lowercase=not args.no_lowercase,
                include_uppercase=not args.uppercase_only,
                uppercase_only=args.uppercase_only
            )
            
            print(f"Generated password: {password}")
            
            # Show strength analysis
            strength = self.generator.check_password_strength(password)
            print(f"Strength: {strength['strength'].replace('_', ' ').title()}")
            print(f"Entropy: {strength['entropy']}")
            
            return 0
        except Exception as e:
            print(f"Failed to generate password: {e}")
            return 1
    
    def _cmd_status(self) -> int:
        """Show vault status."""
        if not self._ensure_unlocked():
            return 1
        
        try:
            stats = self.vault.get_stats()
            
            print("PassSafe Vault Status")
            print("=" * 30)
            print(f"Total items: {stats['total_items']}")
            print(f"Stealth mode: {'ON' if stats['stealth_mode'] else 'OFF'}")
            print(f"Created: {stats['created_at'][:10]}")
            print(f"Last updated: {stats['updated_at'][:10]}")
            
            if stats['categories']:
                print("\nCategories:")
                for cat, count in sorted(stats['categories'].items()):
                    color = get_category_color(cat)
                    reset = "\033[0m"
                    print(f"  {color}{cat}{reset}: {count}")
            
            if stats['old_items'] > 0:
                print(f"\n⚠️  {stats['old_items']} items older than 90 days")
            
            return 0
        except Exception as e:
            print(f"Failed to get status: {e}")
            return 1
    
    def _ensure_unlocked(self) -> bool:
        """Ensure vault is unlocked."""
        if not self.vault or not self.vault.unlocked:
            print("Vault is not locked. Use 'unlock' command first.")
            return False
        return True
    
    def _print_item(self, item: dict, reveal_password: bool = False) -> None:
        """Print password entry details."""
        service = item["service"]
        username = item["username"]
        category = item["category"]
        updated_at = item["updated_at"][:10]
        
        # Color code category
        color = get_category_color(category)
        reset = "\033[0m"
        
        print(f"Service: {service}")
        print(f"Username: {username}")
        print(f"Category: {color}{category}{reset}")
        print(f"Updated: {updated_at}")
        
        if reveal_password:
            password = item["password"]
            print(f"Password: {password}")
        else:
            print("Password: [hidden]")
        
        if item.get("notes"):
            print(f"Notes: {item['notes']}")
        
        print("-" * 40)


def main():
    """Main entry point."""
    cli = PassSafeCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()