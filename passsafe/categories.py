"""
Auto-category detection module for PassSafe CLI.
Automatically categorizes services based on name patterns.
"""

import re
from typing import Dict, List


class ServiceCategorizer:
    """
    Automatically categorizes services based on name patterns.
    """
    
    def __init__(self):
        """Initialize categorizer with patterns."""
        self.patterns = {
            "social": [
                r"facebook", r"instagram", r"twitter", r"linkedin", r"tiktok",
                r"snapchat", r"reddit", r"pinterest", r"tumblr", r"discord",
                r"telegram", r"whatsapp", r"messenger", r"viber", r"signal",
                r"wechat", r"line", r"kakao", r"skype", r"zoom", r"teams"
            ],
            "email": [
                r"gmail", r"outlook", r"yahoo", r"hotmail", r"protonmail",
                r"icloud", r"aol", r"mail\.com", r"zoho", r"fastmail",
                r"tutanota", r"yandex", r"qq\.com", r"163\.com", r"exchange"
            ],
            "finance": [
                r"bank", r"paypal", r"venmo", r"cashapp", r"zelle",
                r"stripe", r"square", r"quickbooks", r"mint", r"y\.n\.a\.b",
                r"robinhood", r"fidelity", r"vanguard", r"schwab", r"etrade",
                r"coinbase", r"binance", r"kraken", r"gemini", r"blockchain",
                r"credit.*card", r"visa", r"mastercard", r"amex", r"discover",
                r"turbotax", r"h&r.*block", r"tax.*act", r"credit.*karma"
            ],
            "work": [
                r"office", r"microsoft", r"azure", r"aws", r"google.*workspace",
                r"slack", r"asana", r"trello", r"jira", r"confluence",
                r"notion", r"evernote", r"onedrive", r"dropbox", r"sharepoint",
                r"github", r"gitlab", r"bitbucket", r"docker", r"kubernetes",
                r"jenkins", r"circleci", r"travis", r"heroku", r"vercel",
                r"netlify", r"digitalocean", r"linode", r"vultr", r"cloudflare"
            ],
            "shopping": [
                r"amazon", r"ebay", r"walmart", r"target", r"best.*buy",
                r"costco", r"home.*depot", r"lowe", r"ikea", r"wayfair",
                r"etsy", r"shopify", r"etsy", r"aliexpress", r"alibaba",
                r"newegg", r"bh.*photo", r"adorama", r"macys", r"nordstrom",
                r"kohls", r"jcpenney", r"sephora", r"ulta", r"walgreens",
                r"cvs", r"rite.*aid", r"whole.*foods", r"trader.*joe"
            ],
            "entertainment": [
                r"netflix", r"hulu", r"disney+", r"prime.*video", r"hbo.*max",
                r"apple.*tv", r"youtube", r"spotify", r"apple.*music", r"pandora",
                r"twitch", r"steam", r"epic.*games", r"xbox", r"playstation",
                r"nintendo", r"blizzard", r"origin", r"uplay", r"gog",
                r"audible", r"kindle", r"goodreads", r"medium", r"substack"
            ],
            "travel": [
                r"airbnb", r"booking\.com", r"expedia", r"kayak", r"priceline",
                r"hotels\.com", r"marriott", r"hilton", r"hyatt", r"ihg",
                r"delta", r"united", r"american", r"southwest", r"jetblue",
                r"uber", r"lyft", r"airline", r"railway", r"amtrak",
                r"enterprise", r"hertz", r"avis", r"budget", r"national"
            ],
            "health": [
                r"mychart", r"epic", r"cerner", r"athena", r"zocdoc",
                r"teladoc", r"amwell", r"doctor.*on.*demand", r"one.*medical",
                r" cvs", r"walgreens", r"rite.*aid", r"express.*scripts",
                r"optum", r"blue.*cross", r"aetna", r"united.*health", r"cigna"
            ],
            "education": [
                r"coursera", r"udemy", r"edx", r"khan", r"skillshare",
                r"linkedin.*learning", r"pluralsight", r"codecademy", r"freecodecamp",
                r"duolingo", r"babbel", r"rosetta", r"memrise", r"anki",
                r"chegg", r"quizlet", r"grammarly", r"turnitin", r"blackboard"
            ]
        }
    
    def categorize_service(self, service_name: str) -> str:
        """
        Automatically categorize a service based on its name.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Category name
        """
        if not service_name:
            return "misc"
        
        service_lower = service_name.lower()
        
        # Check each category pattern
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, service_lower):
                    return category
        
        # Additional heuristics
        if self._is_email_service(service_lower):
            return "email"
        elif self._is_financial_service(service_lower):
            return "finance"
        elif self._is_social_platform(service_lower):
            return "social"
        elif self._is_work_tool(service_lower):
            return "work"
        
        return "misc"
    
    def _is_email_service(self, service: str) -> bool:
        """Check if service is an email provider."""
        email_indicators = ["mail", "email", "inbox", "@", ".com", ".org", ".net"]
        return any(indicator in service for indicator in email_indicators)
    
    def _is_financial_service(self, service: str) -> bool:
        """Check if service is financial."""
        financial_indicators = ["pay", "bank", "money", "card", "invest", "trade", "crypto"]
        return any(indicator in service for indicator in financial_indicators)
    
    def _is_social_platform(self, service: str) -> bool:
        """Check if service is social media."""
        social_indicators = ["chat", "message", "friend", "post", "share", "connect"]
        return any(indicator in service for indicator in social_indicators)
    
    def _is_work_tool(self, service: str) -> bool:
        """Check if service is a work tool."""
        work_indicators = ["work", "office", "business", "project", "team", "collab"]
        return any(indicator in service for indicator in work_indicators)
    
    def get_all_categories(self) -> List[str]:
        """
        Get list of all available categories.
        
        Returns:
            List of category names
        """
        return list(self.patterns.keys()) + ["misc"]
    
    def add_custom_pattern(self, category: str, pattern: str) -> None:
        """
        Add a custom pattern for a category.
        
        Args:
            category: Category name
            pattern: Regex pattern to add
        """
        if category not in self.patterns:
            self.patterns[category] = []
        
        self.patterns[category].append(pattern)
    
    def get_category_stats(self, items: List[Dict]) -> Dict[str, int]:
        """
        Get statistics of categories for given items.
        
        Args:
            items: List of password entries
            
        Returns:
            Dictionary mapping categories to counts
        """
        stats = {}
        
        for item in items:
            service = item.get("service", "")
            category = self.categorize_service(service)
            
            stats[category] = stats.get(category, 0) + 1
        
        return stats
    
    def suggest_category(self, service_name: str, current_category: str = None) -> str:
        """
        Suggest a category for a service, with confidence scoring.
        
        Args:
            service_name: Name of the service
            current_category: Currently assigned category (if any)
            
        Returns:
            Suggested category
        """
        suggested = self.categorize_service(service_name)
        
        # If current category matches suggestion, keep it
        if current_category and current_category == suggested:
            return current_category
        
        return suggested


def categorize_service(service_name: str) -> str:
    """
    Convenience function to categorize a service.
    
    Args:
        service_name: Name of the service
        
    Returns:
        Category name
    """
    categorizer = ServiceCategorizer()
    return categorizer.categorize_service(service_name)


def get_category_color(category: str) -> str:
    """
    Get a color code for a category (for terminal output).
    
    Args:
        category: Category name
        
    Returns:
        ANSI color code
    """
    colors = {
        "social": "\033[95m",      # Magenta
        "email": "\033[94m",       # Blue
        "finance": "\033[92m",      # Green
        "work": "\033[93m",         # Yellow
        "shopping": "\033[91m",    # Red
        "entertainment": "\033[96m", # Cyan
        "travel": "\033[97m",      # White
        "health": "\033[90m",      # Gray
        "education": "\033[94m",   # Blue
        "misc": "\033[90m"          # Gray
    }
    
    return colors.get(category.lower(), "\033[90m") + "\033[1m"