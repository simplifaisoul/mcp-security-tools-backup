FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV MCP_SERVER_PORT=8000
ENV MAX_SCAN_TIMEOUT=300

# Install security tools and Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    libcap2-bin \
    nmap \
    nikto \
    sqlmap \
    wpscan \
    dirb \
    exploitdb \
    aircrack-ng \
    gobuster \
    sublist3r \
    wapiti \
    metasploit-framework \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash mcpuser && \
    chown -R mcpuser:mcpuser /home/mcpuser

# Set network capabilities for nmap (non-root execution)
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap || true

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies (using --break-system-packages for Kali)
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy server code
COPY server.py .

# Switch to non-root user
USER mcpuser

# Expose MCP server port
EXPOSE 8000

# Run the server
CMD ["python3", "server.py"]