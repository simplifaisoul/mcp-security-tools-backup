# MCP Security Tools Server

A Model Context Protocol (MCP) server providing security scanning tools wrapped in FastMCP, running in a Kali Linux Docker container.

## Quick Start

1. **Build the Docker image:**
   ```bash
   docker-compose build
   ```

2. **Configure Cursor:**
   The MCP server is already configured in `C:\Users\mrads\.cursor\mcp.json`

3. **Restart Cursor** to load the new MCP server

4. **Use the tools** through Cursor's MCP interface

## Monitoring Containers

### Real-Time Monitoring Script

Use the provided PowerShell script to monitor containers in real-time:

```powershell
.\monitor-mcp-containers.ps1
```

### Manual Monitoring

**View running containers:**
```bash
docker ps --filter ancestor=mcp-security-tools-mcp-security-tools
```

**View container logs:**
```bash
docker logs -f CONTAINER_ID
```

**Monitor container events:**
```bash
docker events --filter image=mcp-security-tools-mcp-security-tools
```

**View resource usage:**
```bash
docker stats
```

## Available Tools

- **nmap_scan** - Network mapping and port scanning
- **nikto_scan** - Web server vulnerability scanner  
- **sqlmap_scan** - SQL injection detection and exploitation
- **wpscan_scan** - WordPress security scanner
- **dirb_scan** - Web content/directory scanner
- **searchsploit_search** - Exploit Database search

## Documentation

For detailed information about how the system works, container lifecycle, and monitoring, see:

- **[MCP-Security-Tools-Deep-Dive.md](./MCP-Security-Tools-Deep-Dive.md)** - Comprehensive guide covering architecture, Docker monitoring, troubleshooting, and more

## Configuration

Edit `.env` file or set environment variables in `docker-compose.yml`:

- `MCP_SERVER_PORT` - Server port (default: 8000)
- `MAX_SCAN_TIMEOUT` - Maximum scan timeout in seconds (default: 300)
- `ALLOWED_IPS` - Comma-separated list of allowed IP ranges
- `BLOCKED_IPS` - Comma-separated list of blocked IPs

## Security

⚠️ **Legal Disclaimer**: This tool is provided for authorized security testing only. Unauthorized use against systems you don't own or have permission to test is illegal and unethical.

✅ **Best Practices**:
- Always get written permission before scanning
- Use only on systems you own or have explicit authorization
- Respect rate limits and don't overload targets
- Review scan results carefully
- Keep security tools updated

## Troubleshooting

See the [Deep Dive Guide](./MCP-Security-Tools-Deep-Dive.md#troubleshooting) for detailed troubleshooting steps.

## Project Structure

```
mcp-security-tools/
├── Dockerfile              # Kali Linux container definition
├── server.py              # FastMCP server with all tools
├── requirements.txt       # Python dependencies
├── docker-compose.yml     # Docker Compose configuration
├── .env                   # Environment variables
├── .dockerignore          # Docker ignore patterns
├── monitor-mcp-containers.ps1  # Monitoring script
├── MCP-Security-Tools-Deep-Dive.md  # Detailed documentation
└── README.md              # This file
```