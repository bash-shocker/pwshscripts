<#
.SYNOPSIS
Discover reachable hosts and reachable subnets and optionally export as plain text files.
 
.DESCRIPTION
- Identical discovery behavior to previous script: interfaces, routes, ARP neighbors, traceroute inference, ICMP liveness checks.
- When -ExportText is used, writes ReachableHosts.txt and ReachableSubnets.txt in the current folder.
#>
 
param(
    [string[]]$TraceTargets = @('8.8.8.8','1.1.1.1'),
    [int]$PingTimeoutMs = 800,
    [ValidateRange(1,500)][int]$Threads = 100,
    [int]$TracerouteMaxHops = 30,
    [switch]$ExportText
)
 
function Get-LocalNetworkInfo {
    $interfaces = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressState
    $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Select-Object DestinationPrefix,NextHop,RouteMetric
    $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                 Where-Object { $_.IPAddress -and $_.LinkLayerAddress -ne 'ff-ff-ff-ff-ff-ff' } |
                 Select-Object IPAddress,LinkLayerAddress,InterfaceIndex,State
    [PSCustomObject]@{
        Interfaces = $interfaces
        Routes     = $routes
        Neighbors  = $neighbors
    }
}
 
function Run-Traceroutes {
    param([string[]]$Targets, [int]$MaxHops=30)
    $hops = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($t in $Targets) {
        Write-Verbose "Traceroute to $t"
        $lines = tracert -d -h $MaxHops $t 2>$null
        foreach ($line in $lines) {
            if ($line -match '\s+\d+\s+([0-9\.]+)') {
                $ip = $matches[1]
                if ($ip -and $ip -ne '*') { $hops.Add($ip) | Out-Null }
            }
        }
    }
    return $hops.ToArray()
}
 
function Infer-SubnetsFromIPs {
    param([string[]]$IPs)
    $out = foreach ($ip in $IPs) {
        try {
            $addr = [System.Net.IPAddress]::Parse($ip)
            $b = $addr.GetAddressBytes()
            $base30 = [int]([math]::Floor($b[3]/4)*4)
            [PSCustomObject]@{
                HopIP = $ip
                Inferred30 = "{0}.{1}.{2}.{3}/30" -f $b[0],$b[1],$b[2],$base30
                Inferred24 = "{0}.{1}.{2}.0/24" -f $b[0],$b[1],$b[2]
            }
        } catch { }
    }
    return $out
}
 
# ---------- ICMP test (returns bool) ----------
function Test-ICMP {
    param([string]$IP, [int]$TimeoutMs=800)
    try {
        $p = New-Object System.Net.NetworkInformation.Ping
        $r = $p.Send($IP, $TimeoutMs)
        return ($r.Status -eq 'Success')
    } catch { return $false }
}
 
# ---------- Main ----------
Write-Host "`n[*] Gathering local network info..." -ForegroundColor Cyan
$net = Get-LocalNetworkInfo
$interfaces = $net.Interfaces
$routes = $net.Routes
$neighbors = $net.Neighbors
 
Write-Host "`nInterfaces (IPv4):"
$interfaces | Format-Table -AutoSize
 
Write-Host "`nNon-default Routes (DestinationPrefix):"
$routes | Where-Object { $_.DestinationPrefix -ne '0.0.0.0/0' } | Format-Table -AutoSize
 
Write-Host "`nARP / Neighbors (local L2):"
$neighbors | Format-Table -AutoSize
 
# traceroute inference
Write-Host "`n[*] Running traceroutes to infer upstream/link subnets..."
$traceHops = @()
try { $traceHops = Run-Traceroutes -Targets $TraceTargets -MaxHops $TracerouteMaxHops } catch { Write-Warning "Traceroute failed or not available on this host." }
if ($traceHops.Count -gt 0) {
    Write-Host "`nTraceroute hops found:"; $traceHops | ForEach-Object { Write-Host $_ }
}
$inferred = Infer-SubnetsFromIPs -IPs $traceHops
if ($inferred) {
    Write-Host "`nInferred subnets from traceroute hops:"
    $inferred | Format-Table -AutoSize
}
 
# candidates set
$candidates = [System.Collections.Generic.HashSet[string]]::new()
 
# Add ARP neighbors
foreach ($n in $neighbors) { $candidates.Add($n.IPAddress) | Out-Null }
 
# Add interface IPs
foreach ($i in $interfaces) { $candidates.Add($i.IPAddress) | Out-Null }
 
# Add route NextHops (non-zero)
foreach ($r in $routes) {
    if ($r.NextHop -and $r.NextHop -ne '0.0.0.0') { $candidates.Add($r.NextHop) | Out-Null }
}
 
# Add traceroute hops
foreach ($h in $traceHops) { $candidates.Add($h) | Out-Null }
 
$candidateList = $candidates.ToArray()
Write-Host "`nCandidates to check for liveness: $($candidateList.Count)"
 
# Parallel ICMP checks using runspaces
$alive = [System.Collections.ArrayList]::new()
if ($candidateList.Count -gt 0) {
    $pool = [runspacefactory]::CreateRunspacePool(1, [math]::Min($Threads, $candidateList.Count))
    $pool.Open()
    $jobs = @()
    foreach ($ip in $candidateList) {
        $ps = [powershell]::Create().AddScript({
            param($ip,$timeout)
            try {
                $p = New-Object System.Net.NetworkInformation.Ping
                $r = $p.Send($ip, $timeout)
                if ($r.Status -eq 'Success') {
                    [PSCustomObject]@{ IP = $ip; Method = 'ICMP'; LastSeen = (Get-Date).ToString('o') }
                } else { $null }
            } catch { $null }
        }).AddParameters($ip, $PingTimeoutMs)
        $ps.RunspacePool = $pool
        $async = $ps.BeginInvoke()
        $jobs += [PSCustomObject]@{ Pipe = $ps; Async = $async; IP = $ip }
    }
 
    # collect results
    while ($jobs.Count -gt 0) {
        $done = $jobs | Where-Object { $_.Async.IsCompleted }
        if (-not $done) { Start-Sleep -Milliseconds 200; continue }
        foreach ($d in $done) {
            try {
                $res = $d.Pipe.EndInvoke($d.Async)
                $d.Pipe.Dispose()
                if ($res) { $alive.Add($res) | Out-Null }
            } catch { }
            $jobs = $jobs | Where-Object { $_ -ne $d }
        }
    }
    $pool.Close(); $pool.Dispose()
}
 
# Add ARP-only entries (present but not ICMP alive)
$arpOnly = $neighbors | Where-Object {
    -not ($alive | Where-Object { $_.IP -eq $_.IPAddress })
} | ForEach-Object { [PSCustomObject]@{ IP = $_.IPAddress; Method = 'ARP'; LastSeen = (Get-Date).ToString('o') } }
 
# Merge reachable
$reachable = @()
$reachable += $alive
$reachable += $arpOnly
 
Write-Host "`nReachable hosts count: $($reachable.Count)`n"
if ($reachable.Count -gt 0) {
    $reachable | Format-Table IP,Method,LastSeen -AutoSize
} else {
    Write-Host "No reachable hosts detected via ICMP or ARP." -ForegroundColor Yellow
}
 
# Build reachable subnets: route prefixes + inferred
$subnets = [System.Collections.ArrayList]::new()
foreach ($r in $routes | Where-Object { $_.DestinationPrefix -ne '0.0.0.0/0' }) {
    $subnets.Add([PSCustomObject]@{ Source = 'RouteTable'; Prefix = $r.DestinationPrefix; Detail = $r.NextHop }) | Out-Null
}
foreach ($i in $inferred) {
    $subnets.Add([PSCustomObject]@{ Source = 'TracerouteInference'; Prefix = $i.Inferred24; Detail = $i.HopIP }) | Out-Null
}
 
if ($subnets.Count -gt 0) {
    Write-Host "`nReachable subnets (routes + inferred):"
    $subnets | Format-Table -AutoSize
} else {
    Write-Host "`nNo non-default route prefixes or traceroute inferences found." -ForegroundColor Yellow
}
 
# ---------- Export as plain text if requested ----------
if ($ExportText) {
    $hostsFile = Join-Path -Path (Get-Location) -ChildPath 'ReachableHosts.txt'
    $subnetsFile = Join-Path -Path (Get-Location) -ChildPath 'ReachableSubnets.txt'
 
    # Write hosts header
    "Reachable Hosts - Generated: $((Get-Date).ToString('o'))" | Out-File -FilePath $hostsFile -Encoding utf8
    "IP | Method | LastSeen" | Out-File -FilePath $hostsFile -Encoding utf8 -Append
    "-" * 80 | Out-File -FilePath $hostsFile -Encoding utf8 -Append
 
    foreach ($h in $reachable) {
        "$($h.IP) | $($h.Method) | $($h.LastSeen)" | Out-File -FilePath $hostsFile -Encoding utf8 -Append
    }
 
    # Write subnets header
    "Reachable Subnets - Generated: $((Get-Date).ToString('o'))" | Out-File -FilePath $subnetsFile -Encoding utf8
    "Source | Prefix | NextHop/HopIP" | Out-File -FilePath $subnetsFile -Encoding utf8 -Append
    "-" * 80 | Out-File -FilePath $subnetsFile -Encoding utf8 -Append
 
    foreach ($s in $subnets) {
        "$($s.Source) | $($s.Prefix) | $($s.Detail)" | Out-File -FilePath $subnetsFile -Encoding utf8 -Append
    }
 
    Write-Host "`nExported plain text files:" -ForegroundColor Green
    Write-Host " - $hostsFile"
    Write-Host " - $subnetsFile"
}
 
Write-Host "`nDiscovery complete.`n" -ForegroundColor Cyan
