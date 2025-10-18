<#
.SYNOPSIS
  Enumerate reachable subnets and scan specific TCP/UDP ports (corrected network math).

.DESCRIPTION
  - Finds local IPv4 interfaces and derives networks (CIDR).
  - Expands CIDR to hosts (with safety cap).
  - Optional ping sweep to find alive hosts.
  - Scans TCP and UDP ports on alive hosts.
  - Fixes previous BitConverter / network-address math bug.

.PARAMETER BatchSize
  Safety cap for maximum hosts expanded per-subnet (default 4096).

.PARAMETER UdpTimeout
  UDP receive timeout in ms.

.PARAMETER PortList
  Comma-separated list of ports to check (both TCP and UDP will be tried; adjust if desired).

#>

[CmdletBinding()]
param(
    [int]$BatchSize = 4096,
    [int]$UdpTimeout = 3000,
    [string]$PortList = "81,161,300,591,593,832,981,1010,1311,2075,2076,2082,2087,2095,2096,2480,3000,3128,3306,3333,3366,3868,4000,4040,4044,4243,4567,4711,4712,4993,5000,5104,5108,5432,5673,5800,5900,6000,6443,6543,7000,7077,7080,7396,7443,7447,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8089,8090,8091,8118,8181,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,9999,10000,12443,15672,16080,18091,18092,19000,19080,20720,2801"
)

function Write-Info { param($m) Write-Host "[*] $m" -ForegroundColor Cyan }

# --- Utility: compute network address from IP + prefix (returns network IP string) ---
function ConvertTo-NetworkAddress {
    param(
        [Parameter(Mandatory=$true)][string]$IPAddress,
        [Parameter(Mandatory=$true)][int]$PrefixLength
    )
    # Parse IP bytes
    $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
    # Ensure little-endian numeric by reversing for arithmetic
    [array]::Reverse($ipBytes)
    $ipNum = 0
    for ($i = 0; $i -lt 4; $i++) {
        $ipNum = $ipNum -bor ($ipBytes[$i] -shl (8 * $i))
    }

    # Build netmask numeric
    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) { throw "Invalid prefix: $PrefixLength" }
    $maskNum = ([uint32]::MaxValue) -shl (32 - $PrefixLength)
    $maskNum = $maskNum -band 0xFFFFFFFF

    # Compute network numeric and convert back to dotted quad
    $netNum = $ipNum -band $maskNum
    $b = @()
    for ($i = 0; $i -lt 4; $i++) {
        $b += (($netNum -shr (8 * $i)) -band 0xFF)
    }
    [array]::Reverse($b)
    return ([System.Net.IPAddress]::new([byte[]]$b)).ToString()
}

# --- Utility: expand CIDR to hosts with safety cap ---
function Expand-CidrToHosts {
    param(
        [Parameter(Mandatory=$true)][string]$Cidr,   # e.g. 10.0.1.0/24
        [int]$MaxHosts = 4096
    )

    if ($Cidr -notmatch '^(.+?)\/(\d{1,2})$') {
        throw "CIDR expected in form a.b.c.d/prefix : $Cidr"
    }
    $netIp = $matches[1]
    $prefix = [int]$matches[2]

    if ($prefix -lt 0 -or $prefix -gt 32) { throw "Invalid prefix $prefix" }

    # number of usable hosts (exclude network & broadcast for /31+/32 handling)
    $total = [math]::Pow(2, 32 - $prefix)
    if ($total -le 2) {
        # /31 or /32 -> handle specially: include all (for /32 single host)
        $hostCount = [int]($total)
    } else {
        $hostCount = [int]($total - 2)
    }

    if ($hostCount -gt $MaxHosts) {
        Write-Warning "Subnet $Cidr has $hostCount hosts (greater than MaxHosts $MaxHosts). Skipping expansion."
        return @()
    }

    # Compute first host numeric and last host numeric
    # Convert net IP to numeric
    $netBytes = [System.Net.IPAddress]::Parse($netIp).GetAddressBytes(); [array]::Reverse($netBytes)
    $netNum = 0
    for ($i = 0; $i -lt 4; $i++) { $netNum = $netNum -bor ($netBytes[$i] -shl (8 * $i)) }

    if ($total -le 2) {
        $first = $netNum
        $last = $netNum + $total - 1
    } else {
        $first = $netNum + 1
        $last = $netNum + $total - 2
    }

    $hosts = New-Object System.Collections.ArrayList
    for ($n = $first; $n -le $last; $n++) {
        $bytes = @()
        for ($i = 0; $i -lt 4; $i++) { $bytes += (($n -shr (8 * $i)) -band 0xFF) }
        [array]::Reverse($bytes)
        $ip = [System.Net.IPAddress]::new([byte[]]$bytes).ToString()
        [void]$hosts.Add($ip)
    }
    return ,$hosts
}

# --- Discover local IPv4 networks (CIDR) ---
function Get-LocalCidrs {
    Write-Info "Enumerating local IPv4 addresses and prefixes..."
    $cidrs = @()
    try {
        $addresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -and ($_.PrefixLength -ne $null) -and ($_.IPAddress -notlike "169.254.*") }
        foreach ($a in $addresses) {
            $network = ConvertTo-NetworkAddress -IPAddress $a.IPAddress -PrefixLength $a.PrefixLength
            $cidrs += "$network/$($a.PrefixLength)"
        }
    } catch {
        Write-Warning "Get-NetIPAddress failed or unavailable: $_. Using ipconfig fallback."
        $raw = ipconfig
        # Best-effort grep for IPv4 lines (not robust for all locales); prefer Get-NetIPAddress when available
        $matches = ($raw -split "`n") -match '\d{1,3}(\.\d{1,3}){3}'
        foreach ($m in $matches) {
            if ($m -match '(\d{1,3}(?:\.\d{1,3}){3})') {
                $cidrs += "$($matches[0])/32"
            }
        }
    }
    return ($cidrs | Sort-Object -Unique)
}

# --- Try AD Sub
