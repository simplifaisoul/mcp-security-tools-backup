# MCP Security Tools Server - Deep Dive & Docker Monitoring Guide

## Overview

This document provides a comprehensive explanation of how the MCP (Model Context Protocol) Security Tools Server works, including detailed information about Docker container lifecycle, monitoring, and the complete request flow from Cursor to the security tools and back.

---

## Architecture Overview

```
┌─────────────┐
│   Cursor    │
│   (IDE)     │
└──────┬──────┘
       │ MCP Protocol (JSON-RPC over STDIO)
       │
       ▼
┌─────────────────────────────────────┐
│  Cursor MCP Configuration           │
│  (.cursor/mcp.json)                 │
│  ┌───────────────────────────────┐  │
│  │ kali-security-tools:          │  │
│  │   docker run -i --rm          │  │
│  │   mcp-security-tools...       │  │
│  └───────────────────────────────┘  │
└──────────────┬──────────────────────┘
               │
               │ Executes Docker Command
               ▼
┌─────────────────────────────────────┐
│      Docker Engine                   │
│  ┌───────────────────────────────┐  │
│  │ Creates Container Instance     │  │
│  │ (on-demand, ephemeral)         │  │
│  └───────────────────────────────┘  │
└──────────────┬──────────────────────┘
               │
               │ STDIO Connection
               ▼
┌─────────────────────────────────────┐
│  Kali Linux Container                │
│  ┌───────────────────────────────┐  │
│  │ FastMCP Server (server.py)     │  │
│  │  - Receives MCP requests       │  │
│  │  - Validates & sanitizes input │  │
│  │  - Executes security tools     │  │
│  │  - Returns results             │  │
│  └───────────────────────────────┘  │
│                                      │
│  Security Tools Available:          │
│  • nmap                              │
│  • nikto                              │
│  • sqlmap                             │
│  • wpscan                             │
│  • dirb                               │
│  • searchsploit                       │
└──────────────────────────────────────┘
```

---

## How It Works: Step-by-Step Flow

### 1. **User Initiates Tool Request in Cursor**

When you use an MCP tool in Cursor (e.g., `nmap_scan`), here's what happens:

```
User Action: "Scan 192.168.1.1 with nmap"
    ↓
Cursor MCP Client
    ↓
Reads .cursor/mcp.json configuration
    ↓
Executes: docker run -i --rm mcp-security-tools-mcp-security-tools python3 server.py
```

### 2. **Docker Container Creation (On-Demand)**

**Key Point**: Containers are created **on-demand** and are **ephemeral** (temporary). Each tool invocation creates a new container instance.

```bash
# What happens behind the scenes:
docker run -i --rm \
  mcp-security-tools-mcp-security-tools \
  python3 server.py
```

**Flags Explained:**
- `-i` (interactive): Keeps STDIN open, allowing Cursor to send JSON-RPC messages
- `--rm`: Automatically removes the container when it exits (cleanup)
- Container name: `mcp-security-tools-mcp-security-tools` (from docker-compose build)

### 3. **FastMCP Server Initialization**

Inside the container, `server.py` starts:

```python
# server.py initialization
mcp = FastMCP("MCP Security Tools Server")
# Registers all tools: nmap_scan, nikto_scan, sqlmap_scan, etc.
# Waits for STDIN input (JSON-RPC messages)
```

**What you'll see in logs:**
```
╭──────────────────────────────────────────────────────────────╮
│                  🖥  Server name: MCP Security Tools Server    │
│                  📦 Transport:   STDIO                        │
╰──────────────────────────────────────────────────────────────╯
[INFO] Starting MCP server 'MCP Security Tools Server' with transport 'stdio'
```

### 4. **MCP Protocol Communication**

Cursor sends JSON-RPC messages via STDIN:

**Initialize Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {
      "name": "cursor",
      "version": "1.0.0"
    }
  }
}
```

**Tool Call Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "nmap_scan",
    "arguments": {
      "target": "192.168.1.1",
      "scan_type": "default",
      "ports": "1-1000"
    }
  }
}
```

### 5. **Input Validation & Sanitization**

Before executing any tool, the server validates and sanitizes all inputs:

```python
def sanitize_input(value: str, max_length: int = 1000) -> str:
    """Sanitize and validate input"""
    if not value or len(value) > max_length:
        raise ValueError(f"Input too long or empty (max {max_length} chars)")
    
    # Remove potentially dangerous characters
    value = re.sub(r'[;&|`$(){}[\]<>]', '', value)
    return value.strip()
```

**Security Features:**
- Length limits on all inputs
- Command injection prevention (removes dangerous characters)
- IP/URL format validation
- Optional IP allowlist/blocklist (via environment variables)

### 6. **Tool Execution**

The server executes the security tool as a subprocess:

```python
cmd = ["nmap", target, "-p", ports]
result = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    timeout=MAX_SCAN_TIMEOUT  # Default: 300 seconds
)
```

**Execution Details:**
- Runs as non-root user (`mcpuser`) for security
- Uses `setcap` capabilities for nmap (allows raw sockets without root)
- Captures both stdout and stderr
- Enforces timeout limits

### 7. **Response Back to Cursor**

The server formats the response:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [{
      "type": "text",
      "text": "Command: nmap -p 1-1000 192.168.1.1\n\nReturn Code: 0\n\nOutput:\n[scan results...]"
    }],
    "isError": false
  }
}
```

### 8. **Container Cleanup**

After the response is sent:
- Container exits (process completes)
- Docker automatically removes the container (`--rm` flag)
- No persistent state remains

---

## Monitoring Docker Containers in Real-Time

### View Running Containers

**Basic Command:**
```bash
docker ps
```

**Watch Containers in Real-Time:**
```bash
# Update every 2 seconds
watch -n 2 docker ps

# On Windows PowerShell:
while ($true) { Clear-Host; docker ps; Start-Sleep -Seconds 2 }
```

**Expected Output When Tool is Running:**
```
CONTAINER ID   IMAGE                                    COMMAND              CREATED         STATUS         PORTS     NAMES
a1b2c3d4e5f6   mcp-security-tools-mcp-security-tools   "python3 server.py"  5 seconds ago   Up 4 seconds             hopeful_curie
```

### Monitor Container Lifecycle

**Watch Container Creation and Destruction:**
```bash
# Linux/Mac:
docker events --filter 'image=mcp-security-tools-mcp-security-tools'

# Windows PowerShell:
docker events --filter 'image=mcp-security-tools-mcp-security-tools'
```

**What You'll See:**
```
2025-11-25T20:58:00.000000000Z container create a1b2c3d4e5f6 (image=mcp-security-tools-mcp-security-tools, name=hopeful_curie)
2025-11-25T20:58:01.000000000Z container start a1b2c3d4e5f6
2025-11-25T20:58:30.000000000Z container die a1b2c3d4e5f6 (exitCode=0)
2025-11-25T20:58:30.000000000Z container destroy a1b2c3d4e5f6
```

### View Container Logs (Live)

**While Container is Running:**
```bash
# Get container ID first
docker ps

# View logs (replace CONTAINER_ID)
docker logs -f CONTAINER_ID

# Or watch all containers with this image:
docker ps -q --filter ancestor=mcp-security-tools-mcp-security-tools | ForEach-Object { docker logs -f $_ }
```

**What You'll See in Logs:**
```
╭──────────────────────────────────────────────────────────────╮
│                  🖥  Server name: MCP Security Tools Server  │
│                  📦 Transport:   STDIO                       │
╰──────────────────────────────────────────────────────────────╯

[INFO] Starting MCP server 'MCP Security Tools Server' with transport 'stdio'
[INFO] Received request: tools/call
[INFO] Executing: nmap -p 1-1000 192.168.1.1
[INFO] Command completed with exit code 0
```

### Monitor Resource Usage

**View Container Resource Stats:**
```bash
# Real-time stats for all containers
docker stats

# For specific container
docker stats CONTAINER_ID

# One-time snapshot
docker stats --no-stream
```

**Expected Output:**
```
CONTAINER ID   NAME            CPU %     MEM USAGE / LIMIT     MEM %     NET I/O     BLOCK I/O
a1b2c3d4e5f6   hopeful_curie   15.23%    45.2MiB / 2GiB       2.21%     1.2kB / 0B  0B / 0B
```

### Track Container History

**View All Containers (Including Stopped):**
```bash
docker ps -a --filter ancestor=mcp-security-tools-mcp-security-tools
```

**View Container Details:**
```bash
docker inspect CONTAINER_ID
```

**Get Container Exit Code:**
```bash
docker inspect -f '{{.State.ExitCode}}' CONTAINER_ID
# 0 = success, non-zero = error
```

---

## Understanding Container Lifecycle

### Lifecycle States

1. **Created** → Container is created but not started
2. **Running** → Container is active, processing requests
3. **Exited** → Container has stopped (normal completion)
4. **Removed** → Container is deleted (automatic with `--rm`)

### Typical Lifecycle Timeline

```
Time    State       Description
─────────────────────────────────────────────────────────
0s      Created     Docker creates container instance
1s      Running     FastMCP server starts, waits for STDIN
2s      Running     Cursor sends initialize request
3s      Running     Cursor sends tool call request
4s      Running     Server validates input, executes tool
30s     Running     Tool execution (nmap scan in progress)
35s     Running     Tool completes, server formats response
36s     Exited      Server sends response, exits cleanly
36s     Removed     Docker removes container (--rm flag)
```

### Why Ephemeral Containers?

**Benefits:**
- ✅ **Security**: No persistent state, each execution is isolated
- ✅ **Cleanliness**: No leftover containers cluttering the system
- ✅ **Consistency**: Fresh environment for each tool execution
- ✅ **Resource Efficiency**: Containers only exist when needed

**Trade-offs:**
- ⚠️ Slight startup overhead (~1-2 seconds per invocation)
- ⚠️ No persistent cache between invocations

---

## Advanced Monitoring Scripts

### PowerShell: Monitor MCP Containers

Create `monitor-mcp-containers.ps1`:

```powershell
# Monitor MCP Security Tools Containers
Write-Host "Monitoring MCP Security Tools Containers..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

while ($true) {
    Clear-Host
    Write-Host "=== MCP Security Tools Container Status ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Show running containers
    $containers = docker ps --filter ancestor=mcp-security-tools-mcp-security-tools --format "table {{.ID}}\t{{.Status}}\t{{.CreatedAt}}"
    if ($containers) {
        Write-Host "Running Containers:" -ForegroundColor Green
        Write-Host $containers
    } else {
        Write-Host "No containers currently running" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "=== Recent Container History (Last 5) ===" -ForegroundColor Cyan
    docker ps -a --filter ancestor=mcp-security-tools-mcp-security-tools --format "table {{.ID}}\t{{.Status}}\t{{.CreatedAt}}\t{{.Names}}" | Select-Object -First 6
    
    Write-Host ""
    Write-Host "Last updated: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Gray
    Start-Sleep -Seconds 2
}
```

**Usage:**
```powershell
.\monitor-mcp-containers.ps1
```

### Bash: Container Event Monitor

Create `monitor-mcp-events.sh`:

```bash
#!/bin/bash
echo "Monitoring MCP Security Tools Container Events..."
echo "Press Ctrl+C to stop"
echo ""

docker events --filter 'image=mcp-security-tools-mcp-security-tools' --format '{{.Time}} | {{.Status}} | {{.ID}} | {{.Actor.Attributes.name}}'
```

---

## Configuration Deep Dive

### MCP Configuration File

**Location:** `C:\Users\mrads\.cursor\mcp.json`

```json
{
  "mcpServers": {
    "kali-security-tools": {
      "command": "docker",
      "args": [
        "run",
        "-i",           // Interactive mode (STDIN)
        "--rm",         // Auto-remove on exit
        "mcp-security-tools-mcp-security-tools",
        "python3",
        "server.py"
      ],
      "env": {}
    }
  }
}
```

**Configuration Explained:**
- `command`: The executable to run (docker)
- `args`: Arguments passed to docker
  - `run`: Create and start a new container
  - `-i`: Keep STDIN open (required for MCP communication)
  - `--rm`: Remove container automatically when it exits
  - Image name: The Docker image to use
  - `python3 server.py`: Command to run inside container
- `env`: Environment variables (empty in this case, but can be used for configuration)

### Environment Variables

You can configure the server behavior via environment variables in the MCP config:

```json
{
  "mcpServers": {
    "kali-security-tools": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e", "MAX_SCAN_TIMEOUT=600",
        "-e", "ALLOWED_IPS=192.168.1.0/24",
        "mcp-security-tools-mcp-security-tools",
        "python3",
        "server.py"
      ],
      "env": {}
    }
  }
}
```

**Available Environment Variables:**
- `MAX_SCAN_TIMEOUT`: Maximum execution time in seconds (default: 300)
- `ALLOWED_IPS`: Comma-separated list of allowed IP ranges
- `BLOCKED_IPS`: Comma-separated list of blocked IPs

---

## Troubleshooting

### Container Won't Start

**Check Docker is Running:**
```bash
docker ps
```

**Check Image Exists:**
```bash
docker images | grep mcp-security-tools
```

**Rebuild if Needed:**
```bash
cd C:\Users\mrads\mcp-security-tools
docker-compose build
```

### Container Starts But Exits Immediately

**Check Logs:**
```bash
docker logs CONTAINER_ID
```

**Common Issues:**
- Missing dependencies in container
- Python script errors
- Permission issues

**Debug by Running Interactively:**
```bash
docker run -it --rm mcp-security-tools-mcp-security-tools /bin/bash
# Then manually run: python3 server.py
```

### Tool Execution Fails

**Check Tool Availability:**
```bash
docker run --rm mcp-security-tools-mcp-security-tools which nmap
docker run --rm mcp-security-tools-mcp-security-tools which nikto
```

**Test Tool Directly:**
```bash
docker run --rm mcp-security-tools-mcp-security-tools nmap --version
```

### No Containers Appearing

**Verify MCP Configuration:**
- Check `.cursor/mcp.json` syntax is valid JSON
- Ensure Cursor has been restarted after configuration changes
- Check Cursor MCP logs (if available)

**Test Docker Command Manually:**
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | docker run -i --rm mcp-security-tools-mcp-security-tools python3 server.py
```

---

## Security Considerations

### Container Isolation

- Each container execution is isolated
- No persistent storage between invocations
- Runs as non-root user (`mcpuser`)
- Network capabilities limited to what's needed

### Input Sanitization

All inputs are validated and sanitized:
- Length limits enforced
- Dangerous characters removed
- IP/URL format validation
- Optional IP allowlist/blocklist

### Resource Limits

- Timeout limits on all tool executions
- Container automatically removed after use
- No persistent processes

---

## Performance Characteristics

### Startup Time

- Container creation: ~0.5-1 second
- FastMCP initialization: ~0.1-0.2 seconds
- Total overhead: ~1-2 seconds per tool invocation

### Execution Time

- Depends on the tool and scan parameters
- nmap: 5-60 seconds (typical)
- nikto: 10-120 seconds
- sqlmap: 30-300+ seconds
- All subject to `MAX_SCAN_TIMEOUT` limit

### Resource Usage

- Memory: ~40-100 MB per container
- CPU: Varies by tool (nmap can be CPU-intensive)
- Network: Depends on scan type and target

---

## Best Practices

### Monitoring

1. **Regular Monitoring**: Use `docker ps` to verify containers are being created
2. **Log Review**: Check logs if tools fail unexpectedly
3. **Resource Monitoring**: Use `docker stats` during heavy usage

### Configuration

1. **Timeouts**: Set appropriate `MAX_SCAN_TIMEOUT` for your use case
2. **IP Restrictions**: Use `ALLOWED_IPS` in production environments
3. **Regular Updates**: Rebuild container image when security tools are updated

### Usage

1. **Authorized Targets Only**: Only scan systems you own or have permission to test
2. **Rate Limiting**: Be mindful of scan frequency to avoid overwhelming targets
3. **Result Review**: Always review scan results carefully

---

## Summary

The MCP Security Tools Server provides a secure, isolated way to run security scanning tools through Cursor. Key points:

- **On-Demand Execution**: Containers are created only when tools are invoked
- **Ephemeral**: Containers are automatically cleaned up after use
- **Secure**: Input validation, non-root execution, isolated environment
- **Observable**: Full Docker lifecycle can be monitored via standard Docker commands
- **Flexible**: Configurable via environment variables and MCP configuration

By understanding the container lifecycle and monitoring techniques described in this guide, you can effectively observe, debug, and optimize your security tool usage within Cursor.

---

## Related Files

- `server.py` - FastMCP server implementation
- `Dockerfile` - Container image definition
- `docker-compose.yml` - Container orchestration
- `.cursor/mcp.json` - Cursor MCP configuration
- `requirements.txt` - Python dependencies

---

*Last Updated: 2025-11-25*