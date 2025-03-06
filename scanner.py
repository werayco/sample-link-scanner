import re
import whois
import socket
from urllib.parse import urlparse
import ssl

def Find(string):
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    urls = re.findall(regex, string)
    return [x[0] for x in urls]

def get_ssl_certificate(url):
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            return "No SSL (HTTP site, might be unsafe)."

        hostname = parsed_url.netloc
        port = 443  

        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "Issued To": cert.get("subject", [["Unknown"]])[0][0][1],
                    "Issued By": cert.get("issuer", [["Unknown"]])[0][0][1],
                    "Valid From": cert.get("notBefore", "Unknown"),
                    "Valid Until": cert.get("notAfter", "Unknown"),
                    "Serial Number": cert.get("serialNumber", "Unknown"),
                }
    except Exception as e:
        return f"SSL Error: {e}"

def check_whois(domain_name):
    try:
        domain = whois.whois(domain_name)
        if domain.domain_name:
            return {
                "Domain Name": domain.domain_name,
                "Registrar": domain.registrar,
                "Creation Date": domain.creation_date,
                "Expiration Date": domain.expiration_date,
                "Name Servers": domain.name_servers,
            }
        else:
            return "WHOIS lookup failed: No domain record found."
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

def analyze_urls(text):
    """Extracts URLs, checks SSL certificates (if HTTPS), performs WHOIS lookup, and determines safety."""
    urls = Find(text)
    results = {}

    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path.split('/')[0]  # Extract domain

        ssl_info = get_ssl_certificate(url)
        whois_info = check_whois(domain)
        is_ssl_valid = isinstance(ssl_info, dict) 
        is_whois_valid = isinstance(whois_info, dict)  

        if is_ssl_valid and is_whois_valid:
            safety_status = "The link is SAFE."
        else:
            safety_status = "The link MAY BE UNSAFE."

        results[url] = {
            "Safety Status": safety_status,
            "SSL Certificate": ssl_info,
            "WHOIS Data": whois_info,
        }

    return results
    
import streamlit as st

st.title("Link Scanner Demo")
st.write("Kindly insert your email sample below:")
user_input = st.text_area("Paste email body or text containing URLs:")

if st.button("Analyze URLs"):
    if user_input.strip():
        results = analyze_urls(user_input)
        
        if results:
            for url, data in results.items():
                st.subheader(f"🔗 URL: {url}")
                st.write(f"**Safety Status:** {data['Safety Status']}")
        else:
            st.warning("No URLs found in the provided text.")
    else:
        st.error("Please enter some text before analyzing.")
