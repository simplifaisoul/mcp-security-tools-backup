# Monitor MCP Security Tools Containers
# This script provides real-time monitoring of Docker containers created by the MCP Security Tools Server

Write-Host "=== MCP Security Tools Container Monitor ===" -ForegroundColor Cyan
Write-Host "Monitoring containers for: mcp-security-tools-mcp-security-tools" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Gray
Write-Host ""

$imageName = "mcp-security-tools-mcp-security-tools"
$updateInterval = 2  # seconds

while ($true) {
    Clear-Host
    Write-Host "=== MCP Security Tools Container Status ===" -ForegroundColor Cyan
    Write-Host "Last updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    # Show running containers
    Write-Host "🟢 RUNNING CONTAINERS:" -ForegroundColor Green
    $running = docker ps --filter "ancestor=$imageName" --format "table {{.ID}}\t{{.Status}}\t{{.CreatedAt}}\t{{.Names}}"
    if ($running -and $running.Count -gt 1) {
        Write-Host $running
    } else {
        Write-Host "  No containers currently running" -ForegroundColor DarkGray
    }
    
    Write-Host ""
    Write-Host "📋 RECENT CONTAINER HISTORY (Last 10):" -ForegroundColor Yellow
    $history = docker ps -a --filter "ancestor=$imageName" --format "table {{.ID}}\t{{.Status}}\t{{.CreatedAt}}\t{{.Names}}" | Select-Object -First 11
    if ($history) {
        Write-Host $history
    } else {
        Write-Host "  No container history found" -ForegroundColor DarkGray
    }
    
    Write-Host ""
    Write-Host "📊 CONTAINER STATISTICS:" -ForegroundColor Magenta
    $stats = docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" --filter "ancestor=$imageName" 2>$null
    if ($stats) {
        Write-Host $stats
    } else {
        Write-Host "  No active containers to show statistics" -ForegroundColor DarkGray
    }
    
    Write-Host ""
    Write-Host "Refreshing in $updateInterval seconds... (Ctrl+C to stop)" -ForegroundColor DarkGray
    Start-Sleep -Seconds $updateInterval
}