# Enumerate reachable networks and scan important ports (TCP/UDP)
param(
    [int]$BatchSize = 4000,
    [int]$UdpTimeout = 5000,
    [string]$Ports = "81,161,300,591,593,832,981,1010,1311,2075,2076,2082,2087,2095,2096,2480,3000,3128,3306,3333,3366,3868,4000,4040,4044,4243,4567,4711,4712,4993,5000,5104,5108,5432,5673,5800,5900,6000,6443,6543,7000,7077,7080,7396,7443,7447,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8089,8090,8091,8118,8181,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,9999,10000,12443,15672,16080,18091,18092,19000,19080,20720,2801"
)

Write-Host "`n[+] Enumerating reachable networks..." -ForegroundColor Cyan

# Discover reachable subnets via ARP + route table
$reachableHosts = @()
$routeTable = Get-NetRoute | Where-Object { $_.DestinationPrefix -notmatch '::|127.0.0.1' -and $_.DestinationPrefix -match '/' } | Select-Object DestinationPrefix,NextHop
$arpEntries = Get-NetNeighbor | Where-Object { $_.State -eq 'Reachable' } | Select-Object IPAddress,LinkLayerAddress

$subnets = @()
foreach ($route in $routeTable) {
    if ($route.DestinationPrefix -match '/') {
        $subnets += $route.DestinationPrefix
    }
}

Write-Host "[+] Found $($subnets.Count) subnets via routing table." -ForegroundColor Yellow

foreach ($subnet in $subnets) {
    Write-Host "  -> $subnet"
}

# Add directly reachable IPs from ARP cache
$reachableHosts += $arpEntries.IPAddress
$reachableHosts = $reachableHosts | Sort-Object -Unique
Write-Host "`n[+] Reachable hosts found via ARP: $($reachableHosts.Count)`n" -ForegroundColor Cyan

# Convert comma-separated ports into array
$portList = $Ports.Split(',') | ForEach-Object { [int]$_.Trim() }

function Test-TCPPort {
    param($Target, $Port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($Target, $Port, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne(500, $false)
        if ($wait -and $tcp.Connected) {
            $tcp.EndConnect($iar)
            $tcp.Close()
            return $true
        } else {
            $tcp.Close()
            return $false
        }
    } catch { return $false }
}

function Test-UDPPort {
    param($Target, $Port)
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $UdpTimeout
        $remote = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($Target)), $Port
        $msg = [System.Text.Encoding]::ASCII.GetBytes("ping")
        $udp.Send($msg, $msg.Length, $remote)
        Start-Sleep -Milliseconds 300
        if ($udp.Available -gt 0) {
            $resp = $udp.Receive([ref]$remote)
            $udp.Close()
            return $true
        } else {
            $udp.Close()
            return $false
        }
    } catch { return $false }
}

Write-Host "`n[+] Starting port scan across reachable hosts...`n" -ForegroundColor Cyan

$results = @()
foreach ($host in $reachableHosts) {
    foreach ($port in $portList) {
        $tcpOpen = Test-TCPPort -Target $host -Port $port
        $udpOpen = Test-UDPPort -Target $host -Port $port
        if ($tcpOpen -or $udpOpen) {
            $results += [PSCustomObject]@{
                Host = $host
                Port = $port
                TCP  = $tcpOpen
                UDP  = $udpOpen
            }
            Write-Host "[+] $host : Port $port open (TCP:$tcpOpen / UDP:$udpOpen)" -ForegroundColor Green
        }
    }
}

Write-Host "`n[+] Scan complete. Reachable services summary:`n" -ForegroundColor Cyan
$results | Format-Table -AutoSize
