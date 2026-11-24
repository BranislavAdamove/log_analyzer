"""Configuration constants for security rules and categorized bot signatures."""

WP_PATHS: list[str] = [
    "/wp-login.php", 
    "/xmlrpc.php"
] 
SENSITIVE_PATHS: list[str] = [
    "/.env",
    "wp-config.php",
    "/phpmyadmin",
    "/.git"
]
BOT_CATEGORIES: dict[str, list[str]] = {
    "Search Engine": [
        "googlebot",
        "bingbot",
        "seznambot",
        "duckduckbot",
        "applebot",
        "yandexbot",
        "baiduspider",
    ],
    "SEO Crawler": [
        "ahrefsbot",
        "semrushbot",
        "mj12bot",
        "dotbot",
        "petalbot",
        "blexbot",
        "rogerbot",
        "screaming frog",
        "serpstatbot",
        "dataforseobot",
    ],
    "AI Scraper": [
        "gptbot",
        "oai-searchbot",
        "claudebot",
        "anthropic-ai",
        "bytespider",
        "ccbot",
        "perplexitybot",
        "amazonbot",
        "meta-externalagent",
        "google-extended",
        "cohere-ai",
    ],
    "Social Preview": [
        "facebookexternalhit",
        "twitterbot",
        "linkedinbot",
        "whatsapp",
        "telegrambot",
        "slackbot",
    ],
    "Security/Scanner": [
        "palo alto",
        "censys",
        "shodan",
        "wpscan",
        "nikto",
        "zgrab",
        "sqlmap",
        "nuclei",
        "masscan",
        "nmap",
        "gobuster",
    ],
    "Generic Script": [
        "python-requests",
        "aiohttp",
        "httpx",
        "urllib",
        "curl/",
        "wget/",
        "go-http-client",
        "axios",
        "node-fetch",
        "libwww-perl",
    ],
}