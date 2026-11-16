WP_PATHS = ["/wp-login.php", "/xmlrpc.php"] 
SENSITIVE_PATHS = ["/.env","wp-config.php","/phpmyadmin","/.git"]
BOT_CATEGORIES = {
    "Search Engine": ["googlebot", "bingbot", "seznambot", "duckduckbot", "applebot"],
    "SEO Crawler": ["ahrefsbot", "semrushbot", "mj12bot", "dotbot", "petalbot", "blexbot"],
    "AI Scraper": ["gptbot", "claudebot", "bytespider", "ccbot", "perplexitybot", "oai-searchbot"],
    "Security/Scanner": ["palo alto", "censys", "shodan", "wpscan", "nikto", "zgrab"],
    "Generic Script": ["python-requests", "curl/", "wget/", "go-http-client"]
}