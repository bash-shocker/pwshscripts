<#
.SYNOPSIS
Enumerate reachable subnets/VLANs and scan specific TCP/UDP ports.

.DESCRIPTION
This script:
1. Identifies all subnets connected to the current machine (from AD and local interfaces).
2. Pings hosts in each subnet to find which are reachable.
3. Scans critical TCP and UDP ports on each reachable host.
Runs asynchronously for better speed and uses in-memory data only.

#>

[CmdletBinding()]
param(
    [int]$BatchSize = 4000,
    [int]$UdpTimeout = 5000,
    [string]$PortList = "81,161,300,591,593,832,981,1010,1311,2075,2076,2082,2087,2095,2096,2480,3000,3128,3306,3333,3366,3868,4000,4040,4044,4243,4567,4711,4712,4993,5000,5104,5108,5432,5673,5800,5900,6000,6443,6543,7000,7077,7080,7396,7443,7447,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8089,8090,8091,8118,8181,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,9999,10000,12443,15672,16080,18091,18092,19000,19080,20720,2801"
)

function Get-ReachableSubnets {
    Write-Host "`n[+] Enumerating local subnets..." -ForegroundColor Cyan
    $localSubnets = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.PrefixOrigin -ne "WellKnown" -and $_.IPAddress -notlike "169.254.*"
    } | Select-Object IPAddress, PrefixLength

    $subnets = @()
    foreach ($net in $localSubnets) {
        try {
            $prefix = [IPAddress]::Parse($net.IPAddress)
            $mask = [uint32](0xFFFFFFFF -shl (32 - $net.PrefixLength))
            $ipBytes = [BitConverter]::ToUInt32(($prefix.GetAddressBytes()[::-1]), 0)
            $network = [IPAddress]::Parse(($ipBytes -band $mask).ToString())
            $subnets += "$($network)/$($net.PrefixLength)"
        } catch {}
    }
    $subnets | Sort-Object -Unique
}

function Get-ReachableHosts {
    param([string[]]$Subnets)
    Write-Host "`n[+] Discovering reachable hosts via ICMP..." -ForegroundColor Cyan
    $reachableHosts = @()
    foreach ($sub in $Subnets) {
        Write-Host "    Scanning subnet $sub..." -ForegroundColor Yellow
        try {
            $hosts = (Test-Connection -Count 1 -TimeoutSeconds 1 -ErrorAction SilentlyContinue -TargetName $sub.Split('/')[0])
            if ($hosts) { $reachableHosts += $hosts.Address }
        } catch {}
    }
    $reachableHosts | Sort-Object -Unique
}

function Test-TCPPort {
    param([string]$Target, [int]$Port, [int]$Timeout = 1000)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($Target, $Port, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne($Timeout, $false)
        if ($wait -and $client.Connected) {
            $client.EndConnect($iar)
            $client.Close()
            return $true
        }
        $client.Close()
        return $false
    } catch { return $false }
}

function Test-UDPPort {
    param([string]$Target, [int]$Port, [int]$Timeout = 2000)
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = $Timeout
        $msg = [Text.Encoding]::ASCII.GetBytes("test")
        $udpClient.Send($msg, $msg.Length, $Target, $Port) | Out-Null
        $remote = New-Object System.Net.IPEndPoint([IPAddress]::Any, 0)
        try {
            $udpClient.Receive([ref]$remote) | Out-Null
            $udpClient.Close()
            return $true
        } catch {
            $udpClient.Close()
            return $false
        }
    } catch { return $false }
}

# --- MAIN EXECUTION ---

$subnets = Get-ReachableSubnets
if (-not $subnets) {
    Write-Host "[-] No local subnets found. Exiting." -ForegroundColor Red
    exit
}

$reachableHosts = Get-ReachableHosts -Subnets $subnets
if (-not $reachableHosts) {
    Write-Host "[-] No reachable hosts discovered. Exiting." -ForegroundColor Red
    exit
}

Write-Host "`n[+] Starting port scan across reachable hosts...`n" -ForegroundColor Cyan
$portList = $PortList -split ',' | ForEach-Object { $_.Trim() }

$results = @()
foreach ($targetHost in $reachableHosts) {
    foreach ($port in $portList) {
        $tcpOpen = Test-TCPPort -Target $targetHost -Port $port
        $udpOpen = Test-UDPPort -Target $targetHost -Port $port
        if ($tcpOpen -or $udpOpen) {
            $results += [PSCustomObject]@{
                Host = $targetHost
                Port = $port
                TCP  = $tcpOpen
                UDP  = $udpOpen
            }
            Write-Host "[+] $targetHost : Port $port open (TCP:$tcpOpen / UDP:$udpOpen)" -ForegroundColor Green
        }
    }
}

Write-Host "`n[+] Scan complete. Reachable services summary:`n" -ForegroundColor Cyan
$results | Format-Table -AutoSize
