"""
Password analyzer module for PassSafe CLI.
Analyzes password security and identifies issues.
"""

import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple
from collections import defaultdict

from .generator import PasswordGenerator


class AnalysisResult:
    """Container for password analysis results."""
    
    def __init__(self):
        self.weak_passwords = []
        self.old_passwords = []
        self.duplicate_passwords = []
        self.unusual_categories = []
        self.total_items = 0
        self.categories = {}
        self.avg_password_length = 0
        self.strength_distribution = defaultdict(int)


class PasswordAnalyzer:
    """
    Analyzes passwords for security issues.
    
    Identifies weak passwords, duplicates, old entries, and other security concerns.
    """
    
    def __init__(self):
        """Initialize password analyzer."""
        self.generator = PasswordGenerator()
        
        # Common weak passwords to check against
        self.common_passwords = {
            "password", "123456", "123456789", "qwerty", "abc123",
            "password123", "admin", "letmein", "welcome", "monkey",
            "1234567890", "password1", "qwerty123", "123123", "dragon",
            "master", "hello", "freedom", "whatever", "qazwsx",
            "trustno1", "123qwe", "1q2w3e4r", "zxcvbnm", "iloveyou"
        }
    
    def analyze_vault(self, items: List[Dict]) -> AnalysisResult:
        """
        Perform comprehensive security analysis of vault items.
        
        Args:
            items: List of password entries
            
        Returns:
            AnalysisResult with all findings
        """
        result = AnalysisResult()
        result.total_items = len(items)
        
        if not items:
            return result
        
        # Track passwords for duplicate detection
        password_hashes = defaultdict(list)
        
        # Track categories
        category_counts = defaultdict(int)
        
        # Track password lengths and strengths
        total_length = 0
        strength_scores = []
        
        # Analyze each item
        for item in items:
            password = item.get("password", "")
            service = item.get("service", "")
            category = item.get("category", "misc")
            updated_at = item.get("updated_at", "")
            
            # Update category tracking
            category_counts[category] += 1
            
            # Analyze password
            if password:
                # Length tracking
                total_length += len(password)
                
                # Strength analysis
                strength_info = self.generator.check_password_strength(password)
                strength_scores.append(strength_info["score"])
                result.strength_distribution[strength_info["strength"]] += 1
                
                # Check for weak passwords
                if self._is_weak_password(password, strength_info):
                    result.weak_passwords.append({
                        "service": service,
                        "issue": f"Weak password ({strength_info['strength']})",
                        "length": len(password),
                        "strength": strength_info["strength"],
                        "suggestions": strength_info["suggestions"]
                    })
                
                # Track for duplicate detection
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                password_hashes[password_hash].append(item)
            
            # Check for old passwords
            if updated_at:
                age_days = self._get_age_in_days(updated_at)
                if age_days > 90:
                    result.old_passwords.append({
                        "service": service,
                        "age_days": age_days,
                        "updated_at": updated_at
                    })
        
        # Find duplicate passwords
        result.duplicate_passwords = self._find_duplicates(password_hashes)
        
        # Find unusual categories
        result.unusual_categories = self._find_unusual_categories(category_counts)
        
        # Calculate statistics
        result.categories = dict(category_counts)
        if items:
            result.avg_password_length = total_length / len(items)
        
        return result
    
    def _is_weak_password(self, password: str, strength_info: Dict) -> bool:
        """
        Check if password meets security criteria.
        
        Args:
            password: Password to check
            strength_info: Pre-computed strength analysis
            
        Returns:
            True if password is considered weak
        """
        # Check length
        if len(password) < 10:
            return True
        
        # Check if in common passwords list
        if password.lower() in self.common_passwords:
            return True
        
        # Check strength score
        if strength_info["score"] < 3:  # Moderate or below
            return True
        
        # Check for common patterns
        if self._has_common_pattern(password):
            return True
        
        return False
    
    def _has_common_pattern(self, password: str) -> bool:
        """
        Check for common weak password patterns.
        
        Args:
            password: Password to check
            
        Returns:
            True if password has common weak patterns
        """
        password_lower = password.lower()
        
        # Sequential characters
        sequences = ["abcdefghijklmnopqrstuvwxyz", "0123456789"]
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in password_lower:
                    return True
        
        # Repeated characters
        if any(char * 3 in password_lower for char in password_lower):
            return True
        
        # Keyboard patterns
        keyboard_patterns = ["qwerty", "asdf", "zxcv", "qaz", "wsx"]
        for pattern in keyboard_patterns:
            if pattern in password_lower:
                return True
        
        return False
    
    def _get_age_in_days(self, iso_date: str) -> int:
        """
        Calculate age in days from ISO date string.
        
        Args:
            iso_date: ISO format date string
            
        Returns:
            Age in days
        """
        try:
            updated = datetime.fromisoformat(iso_date.replace('Z', '+00:00'))
            now = datetime.utcnow()
            return (now - updated).days
        except:
            return 0
    
    def _find_duplicates(self, password_hashes: Dict[str, List[Dict]]) -> List[Dict]:
        """
        Find duplicate passwords.
        
        Args:
            password_hashes: Mapping of password hashes to items
            
        Returns:
            List of duplicate password groups
        """
        duplicates = []
        
        for password_hash, items in password_hashes.items():
            if len(items) > 1:
                services = [item["service"] for item in items]
                duplicates.append({
                    "services": services,
                    "count": len(items),
                    "password_hash": password_hash[:16] + "..."  # Truncated hash
                })
        
        return duplicates
    
    def _find_unusual_categories(self, category_counts: Dict[str, int]) -> List[Dict]:
        """
        Find categories that might be unusual or miscategorized.
        
        Args:
            category_counts: Mapping of category names to counts
            
        Returns:
            List of unusual categories
        """
        usual_categories = {"social", "email", "finance", "work", "misc", "shopping", "entertainment"}
        unusual = []
        
        for category, count in category_counts.items():
            if category.lower() not in usual_categories and count == 1:
                unusual.append({
                    "category": category,
                    "count": count,
                    "suggestion": "Consider categorizing under standard categories"
                })
        
        return unusual
    
    def generate_report(self, result: AnalysisResult) -> str:
        """
        Generate a formatted security report.
        
        Args:
            result: Analysis results
            
        Returns:
            Formatted report string
        """
        lines = []
        lines.append("=" * 50)
        lines.append("PASSSAFE SECURITY ANALYSIS REPORT")
        lines.append("=" * 50)
        lines.append(f"Total Items: {result.total_items}")
        lines.append(f"Average Password Length: {result.avg_password_length:.1f}")
        lines.append("")
        
        # Weak passwords
        if result.weak_passwords:
            lines.append("[WEAK PASSWORDS]")
            for item in result.weak_passwords:
                lines.append(f"  {item['service']} - {item['length']} chars ({item['strength']})")
            lines.append("")
        
        # Old passwords
        if result.old_passwords:
            lines.append("[OLD PASSWORDS]")
            for item in result.old_passwords:
                lines.append(f"  {item['service']} - {item['age_days']} days old")
            lines.append("")
        
        # Duplicate passwords
        if result.duplicate_passwords:
            lines.append("[DUPLICATE PASSWORDS]")
            for item in result.duplicate_passwords:
                services_str = " & ".join(item['services'])
                lines.append(f"  {services_str}")
            lines.append("")
        
        # Unusual categories
        if result.unusual_categories:
            lines.append("[UNUSUAL CATEGORIES]")
            for item in result.unusual_categories:
                lines.append(f"  {item['category']} - {item['suggestion']}")
            lines.append("")
        
        # Strength distribution
        lines.append("[PASSWORD STRENGTH DISTRIBUTION]")
        for strength, count in result.strength_distribution.items():
            percentage = (count / result.total_items) * 100
            lines.append(f"  {strength.replace('_', ' ').title()}: {count} ({percentage:.1f}%)")
        lines.append("")
        
        # Category breakdown
        lines.append("[CATEGORY BREAKDOWN]")
        for category, count in sorted(result.categories.items()):
            lines.append(f"  {category}: {count}")
        lines.append("")
        
        # Summary
        lines.append("[SUMMARY]")
        issues = len(result.weak_passwords) + len(result.old_passwords) + len(result.duplicate_passwords)
        if issues == 0:
            lines.append("  ✅ No security issues found!")
        else:
            lines.append(f"  ⚠️  {issues} security issue(s) found")
            lines.append("  Consider updating weak and old passwords")
            lines.append("  Avoid using duplicate passwords")
        
        lines.append("=" * 50)
        
        return "\n".join(lines)
    
    def get_security_score(self, result: AnalysisResult) -> int:
        """
        Calculate overall security score (0-100).
        
        Args:
            result: Analysis results
            
        Returns:
            Security score from 0 (worst) to 100 (best)
        """
        if result.total_items == 0:
            return 100
        
        score = 100
        
        # Deduct points for weak passwords
        weak_penalty = (len(result.weak_passwords) / result.total_items) * 30
        score -= weak_penalty
        
        # Deduct points for old passwords
        old_penalty = (len(result.old_passwords) / result.total_items) * 20
        score -= old_penalty
        
        # Deduct points for duplicate passwords
        duplicate_penalty = (len(result.duplicate_passwords) / result.total_items) * 25
        score -= duplicate_penalty
        
        # Bonus for strong average password length
        if result.avg_password_length >= 16:
            score += 5
        elif result.avg_password_length >= 12:
            score += 2
        
        # Ensure score stays within bounds
        return max(0, min(100, int(score)))
    
    def get_recommendations(self, result: AnalysisResult) -> List[str]:
        """
        Get security recommendations based on analysis.
        
        Args:
            result: Analysis results
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if result.weak_passwords:
            recommendations.append(f"Update {len(result.weak_passwords)} weak password(s)")
        
        if result.old_passwords:
            recommendations.append(f"Update {len(result.old_passwords)} old password(s) (>90 days)")
        
        if result.duplicate_passwords:
            recommendations.append(f"Fix {len(result.duplicate_passwords)} duplicate password(s)")
        
        if result.avg_password_length < 12:
            recommendations.append("Use longer passwords (12+ characters)")
        
        if result.strength_distribution.get("very_weak", 0) > 0:
            recommendations.append("Avoid very weak passwords")
        
        if result.unusual_categories:
            recommendations.append("Review and standardize categories")
        
        if not recommendations:
            recommendations.append("Great security! Keep it up.")
        
        return recommendations