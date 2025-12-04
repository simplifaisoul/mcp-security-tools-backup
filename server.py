#!/usr/bin/env python3
"""
MCP Security Tools Server using FastMCP
Provides security scanning tools: nmap, nikto, sqlmap, wpscan, dirb, searchsploit, aircrack-ng, gobuster, sublist3r, wapiti, msfvenom
"""

import os
import re
import subprocess
import shlex
from typing import Optional
from fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("MCP Security Tools Server")

# Configuration from environment
MAX_SCAN_TIMEOUT = int(os.getenv("MAX_SCAN_TIMEOUT", "300"))
ALLOWED_IPS = os.getenv("ALLOWED_IPS", "").split(",") if os.getenv("ALLOWED_IPS") else []
BLOCKED_IPS = os.getenv("BLOCKED_IPS", "").split(",") if os.getenv("BLOCKED_IPS") else []


def sanitize_input(value: str, max_length: int = 1000) -> str:
    """Sanitize and validate input"""
    if not value or len(value) > max_length:
        raise ValueError(f"Input too long or empty (max {max_length} chars)")
    
    # Remove potentially dangerous characters
    value = re.sub(r'[;&|`$(){}[\]<>]', '', value)
    return value.strip()


def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, ip))


def validate_url(url: str) -> bool:
    """Basic URL validation"""
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(url_pattern, url))


def check_ip_allowed(ip: str) -> bool:
    """Check if IP is allowed/blocked"""
    if BLOCKED_IPS and any(ip.startswith(blocked.strip()) for blocked in BLOCKED_IPS if blocked.strip()):
        return False
    if ALLOWED_IPS and not any(ip.startswith(allowed.strip()) for allowed in ALLOWED_IPS if allowed.strip()):
        return False
    return True


@mcp.tool()
def nmap_scan(
    target: str,
    scan_type: str = "default",
    ports: Optional[str] = None,
    options: Optional[str] = ""
) -> str:
    """
    Network mapping and port scanning using nmap.
    
    Args:
        target: IP address or hostname to scan
        scan_type: Scan type - "default", "syn", "udp", "tcp", or "ping"
        ports: Port range (e.g., "80,443" or "1-1000")
        options: Additional nmap options
    """
    try:
        target = sanitize_input(target, 100)
        scan_type = sanitize_input(scan_type, 20)
        
        if not validate_ip(target) and not re.match(r'^[a-zA-Z0-9.-]+$', target):
            return f"Error: Invalid target format: {target}"
        
        if not check_ip_allowed(target):
            return f"Error: Target {target} is not allowed"
        
        cmd = ["nmap"]
        
        # Add scan type
        if scan_type == "syn":
            cmd.append("-sS")
        elif scan_type == "udp":
            cmd.append("-sU")
        elif scan_type == "tcp":
            cmd.append("-sT")
        elif scan_type == "ping":
            cmd.append("-sn")
        
        # Add ports
        if ports:
            ports = sanitize_input(ports, 50)
            cmd.extend(["-p", ports])
        
        # Add target
        cmd.append(target)
        
        # Add additional options
        if options:
            options = sanitize_input(options, 200)
            cmd.extend(shlex.split(options))
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_SCAN_TIMEOUT
        )
        
        output = f"Command: {' '.join(cmd)}\n\n"
        output += f"Return Code: {result.returncode}\n\n"
        output += "Output:\n" + result.stdout
        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Scan timed out after {MAX_SCAN_TIMEOUT} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def nikto_scan(
    target: str,
    port: int = 443,
    ssl: bool = True
) -> str:
    """
    Web server vulnerability scanner using nikto.
    
    Args:
        target: Target URL or hostname
        port: Port number (default: 443)
        ssl: Use SSL (default: true)
    """
    try:
        target = sanitize_input(target, 200)
        
        if not validate_url(target) and not re.match(r'^[a-zA-Z0-9.-]+$', target):
            return f"Error: Invalid target format: {target}"
        
        cmd = ["nikto", "-h", target, "-p", str(port)]
        
        if ssl:
            cmd.append("-ssl")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_SCAN_TIMEOUT
        )
        
        output = f"Command: {' '.join(cmd)}\n\n"
        output += f"Return Code: {result.returncode}\n\n"
        output += "Output:\n" + result.stdout
        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Scan timed out after {MAX_SCAN_TIMEOUT} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def sqlmap_scan(
    target: str,
    level: int = 1,
    risk: int = 1
) -> str:
    """
    SQL injection detection and exploitation using sqlmap.
    
    Args:
        target: Target URL with parameter (e.g., "http://example.com/page?id=1")
        level: Risk level 1-5 (default: 1)
        risk: Risk level 1-3 (default: 1)
    """
    try:
        target = sanitize_input(target, 500)
        
        if not validate_url(target):
            return f"Error: Invalid URL format: {target}"
        
        if level < 1 or level > 5:
            return "Error: Level must be between 1 and 5"
        if risk < 1 or risk > 3:
            return "Error: Risk must be between 1 and 3"
        
        cmd = ["sqlmap", "-u", target, "--level", str(level), "--risk", str(risk), "--batch"]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_SCAN_TIMEOUT
        )
        
        output = f"Command: {' '.join(cmd)}\n\n"
        output += f"Return Code: {result.returncode}\n\n"
        output += "Output:\n" + result.stdout
        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Scan timed out after {MAX_SCAN_TIMEOUT} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def wpscan_scan(
    target: str,
    enumerate: Optional[str] = None
) -> str:
    """
    WordPress security scanner using wpscan.
    
    Args:
        target: WordPress site URL
        enumerate: What to enumerate (u=users, p=plugins, t=themes, etc.)
    """
    try:
        target = sanitize_input(target, 200)
        
        if not validate_url(target):
            return f"Error: Invalid URL format: {target}"
        
        cmd = ["wpscan", "--url", target, "--no-banner"]
        
        if enumerate:
            enumerate = sanitize_input(enumerate, 50)
            cmd.extend(["--enumerate", enumerate])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_SCAN_TIMEOUT
        )
        
        output = f"Command: {' '.join(cmd)}\n\n"
        output += f"Return Code: {result.returncode}\n\n"
        output += "Output:\n" + result.stdout
        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Scan timed out after {MAX_SCAN_TIMEOUT} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def dirb_scan(
    target: str,
    wordlist: Optional[str] = None,
    extensions: Optional[str] = None
) -> str:
    """
    Web content scanner / directory brute-forcer using dirb.
    
    Args:
        target: Target URL
        wordlist: Wordlist path (default: common.txt)
        extensions: File extensions to check (comma-separated, e.g., ".php,.html")
    """
    try:
        target = sanitize_input(target, 200)
        
        if not validate_url(target):
            return f"Error: Invalid URL format: {target}"
        
        cmd = ["dirb", target]
        
        if wordlist:
            wordlist = sanitize_input(wordlist, 200)
            cmd.extend(["-w", wordlist])
        
        if extensions:
            extensions = sanitize_input(extensions, 100)
            cmd.extend(["-X", extensions])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_SCAN_TIMEOUT
        )
        
        output = f"Command: {' '.join(cmd)}\n\n"
        output += f"Return Code: {result.returncode}\n\n"
        output += "Output:\n" + result.stdout
        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Scan timed out after {MAX_SCAN_TIMEOUT} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def searchsploit_search(
    query: str,
    type: Optional[str] = None
) -> str:
    """
    Search the Exploit Database using searchsploit.
    
    Args:
        query: Search query
        type: Type filter (webapps, remote, local, dos, etc.)
    """
    try:
        query = sanitize_input(query, 100)
        
        cmd = ["searchsploit", query]
        
        if type:
            type = sanitize_input(type, 50)
            cmd.extend(["-t", type])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        output = f"Command: {' '.join(cmd)}\n\n"
        output += f"Return Code: {result.returncode}\n\n"
        output += "Output:\n" + result.stdout
        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        return output
        
    except subprocess.TimeoutExpired:
        return "Error: Search timed out after 60 seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def aircrack_ng(
    capture_file: str,
    wordlist: str
) -> str:
    """
    Crack WiFi passwords using aircrack-ng.
    
    Args:
        capture_file: Path to the capture file (.cap)
        wordlist: Path to the wordlist file
    """
    try:
        capture_file = sanitize_input(capture_file, 200)
        wordlist = sanitize_input(wordlist, 200)
        
        # Basic validation for file paths
        if not os.path.exists(capture_file):
            return f"Error: Capture file not found: {capture_file}"
        if not os.path.exists(wordlist):
            return f"Error: Wordlist not found: {wordlist}"
            
        cmd = ["aircrack-ng", "-w", wordlist, capture_file]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_SCAN_TIMEOUT
        )
        
        output = f"Command: {' '.join(cmd)}\n\n"
        output += f"Return Code: {result.returncode}\n\n"
        output += "Output:\n" + result.stdout
        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Scan timed out after {MAX_SCAN_TIMEOUT} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def gobuster_scan(
    target_url: str,
    wordlist: str,
    extensions: Optional[str] = None
) -> str:
    """
    Directory and file brute-forcing using gobuster.
    
    Args:
        target_url: Target URL
        wordlist: Path to the wordlist file
        extensions: File extensions to search for (comma-separated, e.g., "php,html")
    """
    try:
        target_url = sanitize_input(target_url, 200)
        wordlist = sanitize_input(wordlist, 200)

        if not validate_url(target_url):
            return f"Error: Invalid URL format: {target_url}"

        if not os.path.exists(wordlist):
            return f"Error: Wordlist not found: {wordlist}"
            
        cmd = ["gobuster", "dir", "-u", target_url, "-w", wordlist]

        if extensions:
            extensions = sanitize_input(extensions, 100)
            cmd.extend(["-x", extensions])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_SCAN_TIMEOUT
        )
        
        output = f"Command: {' '.join(cmd)}\n\n"
        output += f"Return Code: {result.returncode}\n\n"
        output += "Output:\n" + result.stdout
        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Scan timed out after {MAX_SCAN_TIMEOUT} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def sublist3r_scan(
    domain: str
) -> str:
    """
    Subdomain enumeration using Sublist3r.
    
    Args:
        domain: Target domain
    """
    try:
        domain = sanitize_input(domain, 100)

        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return f"Error: Invalid domain format: {domain}"
            
        cmd = ["sublist3r", "-d", domain]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_SCAN_TIMEOUT
        )
        
        output = f"Command: {' '.join(cmd)}\n\n"
        output += f"Return Code: {result.returncode}\n\n"
        output += "Output:\n" + result.stdout
        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Scan timed out after {MAX_SCAN_TIMEOUT} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def wapiti_scan(
    target_url: str
) -> str:
    """
    Web application vulnerability scanner using Wapiti.
    
    Args:
        target_url: Target URL
    """
    try:
        target_url = sanitize_input(target_url, 200)

        if not validate_url(target_url):
            return f"Error: Invalid URL format: {target_url}"
            
        cmd = ["wapiti", "-u", target_url]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_SCAN_TIMEOUT
        )
        
        output = f"Command: {' '.join(cmd)}\n\n"
        output += f"Return Code: {result.returncode}\n\n"
        output += "Output:\n" + result.stdout
        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Scan timed out after {MAX_SCAN_TIMEOUT} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def msfvenom_generate(
    payload: str,
    lhost: str,
    lport: int,
    format: str,
    outfile: Optional[str] = None
) -> str:
    """
    Generate payloads using msfvenom.
    
    Args:
        payload: Payload to generate (e.g., "windows/meterpreter/reverse_tcp")
        lhost: Listening host
        lport: Listening port
        format: Output format (e.g., "exe", "py", "raw")
        outfile: Output file path (optional)
    """
    try:
        payload = sanitize_input(payload, 100)
        lhost = sanitize_input(lhost, 100)
        format = sanitize_input(format, 20)

        if not validate_ip(lhost):
            return f"Error: Invalid LHOST format: {lhost}"
            
        cmd = [
            "msfvenom",
            "-p", payload,
            "LHOST=" + lhost,
            "LPORT=" + str(lport),
            "-f", format,
        ]

        if outfile:
            outfile = sanitize_input(outfile, 200)
            cmd.extend(["-o", outfile])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_SCAN_TIMEOUT
        )
        
        output = f"Command: {' '.join(cmd)}\n\n"
        output += f"Return Code: {result.returncode}\n\n"
        
        if not outfile:
            output += "Output:\n" + result.stdout
        else:
            if result.returncode == 0:
                output += f"Payload saved to {outfile}"
            else:
                output += "Error generating payload."

        if result.stderr:
            output += "\n\nErrors:\n" + result.stderr
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Scan timed out after {MAX_SCAN_TIMEOUT} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == "__main__":
    mcp.run()