import re
import socket

from urllib.parse import urlparse


def analyze_url(url):

    parsed = urlparse(url)

    hostname = parsed.hostname

    if not hostname:

        return {
            "valid_url": False,
            "hostname": None,
            "ip_address": None,
            "dns_resolved": False,
            "https": False,
            "url_length": len(url),
            "indicators": [],
            "indicator_count": 0,
            "threat_score": 0
        }


    hostname = hostname.lower()


    if hostname.startswith("www."):

        hostname = hostname[4:]


    # --------------------------------------------------
    # DNS INFORMATION
    # --------------------------------------------------

    ip_address = None

    dns_resolved = False


    try:

        ip_address = socket.gethostbyname(
            hostname
        )

        dns_resolved = True


    except socket.gaierror:

        dns_resolved = False


    # --------------------------------------------------
    # SECURITY INDICATORS
    # --------------------------------------------------

    indicators = []


    # Check HTTPS
    if parsed.scheme.lower() != "https":

        indicators.append(
            "URL does not use HTTPS"
        )


    # Check @ symbol
    if "@" in url:

        indicators.append(
            "URL contains @ symbol"
        )


    # Check unusually long URL
    if len(url) > 100:

        indicators.append(
            "Unusually long URL"
        )


    # Check long numeric sequence
    if re.search(r"\d{4,}", url):

        indicators.append(
            "URL contains long numeric sequence"
        )


    # Check multiple subdomains
    hostname_parts = hostname.split(".")


    if len(hostname_parts) > 3:

        indicators.append(
            "Multiple subdomains detected"
        )


    # Check hyphen in domain
    if "-" in hostname:

        indicators.append(
            "Domain contains hyphen"
        )


    # Check @ symbol in network location
    if "@" in parsed.netloc:

        indicators.append(
            "Potential user-information deception"
        )


    # --------------------------------------------------
    # THREAT SCORE
    # --------------------------------------------------

    threat_score = 0


    # Each suspicious indicator adds 15 points
    threat_score += len(indicators) * 15


    # Failed DNS resolution adds 15 points
    if not dns_resolved:

        threat_score += 15


    # Maximum score is 100
    threat_score = min(
        threat_score,
        100
    )


    # --------------------------------------------------
    # FINAL THREAT INTELLIGENCE RESULT
    # --------------------------------------------------

    return {

        "valid_url": True,

        "hostname": hostname,

        "ip_address": ip_address,

        "dns_resolved": dns_resolved,

        "https": parsed.scheme.lower() == "https",

        "url_length": len(url),

        "indicators": indicators,

        "indicator_count": len(indicators),

        "threat_score": threat_score

    }