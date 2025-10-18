<#
    .SYNOPSIS
    Powerful asynchronous IPv4 Port Scanner (improved).

    .DESCRIPTION
    This powerful asynchronous IPv4 Port Scanner allows you to scan any Port-Range you want (0 to 65535 supported).
    The result will contain the Port number, Protocol, Service name (if Ports.txt available), Description and the Status.

    .EXAMPLE
    # Scan LPTREDTEAM03 for ports 1-1000
    PS C:\> .\Start-PortScan.ps1 -ComputerName LPTREDTEAM03 -StartPort 1 -EndPort 1000

    .EXAMPLE
    # Scan explicit ports (UDP & TCP)
    PS C:\> .\Start-PortScan.ps1 -ComputerName f3dc2 -Port @('53u','53t','389t','0-1023') -Threads 200 -OutputPath C:\temp\ports.csv

#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$ComputerName,

    # allow 0..65535 (0 sometimes used in user requests; many network APIs treat 0 specially,
    # but the scanner will attempt to test port 0 if explicitly requested)
    [Parameter(Position = 1, ParameterSetName = 'PortRange')]
    [ValidateRange(0, 65535)]
    [int]$StartPort = 1,

    [Parameter(Position = 2, ParameterSetName = 'PortRange')]
    [ValidateRange(0, 65535)]
    [ValidateScript( {
            if ($_ -lt $StartPort)
            {
                Write-Error 'The EndPort cannot be lower than the StartPort'
            }
            else 
            {
                return $true
            }
        })]
    [int]$EndPort = 65535,
    
    [Parameter(Position = 2, ParameterSetName = 'Port')]
    [string[]]$Port,
    
    [int]$Threads = 500,

    [switch]$Force,

    [string]$OutputPath
)

begin
{
    # helper: determine script root even if running in memory
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

    function Test-Port
    {  
        [Cmdletbinding()]
        Param(  
            [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
            [string[]]$ComputerName,

            [Parameter(Mandatory, Position = 1, ValueFromPipelineByPropertyName)]
            [int]$Port,

            [int]$Count = 1,

            [int]$Delay = 500,
        
            [int]$TcpTimeout = 1000,
            [int]$UdpTimeout = 1000,
            [switch]$Tcp,
            [switch]$Udp
        )

        begin
        {  
            if (-not $Tcp -and -not $Udp)
            {
                $Tcp = $true
            }
            #Typically you never do this, but in this case I felt it was for the benefit of the function  
            #as any errors will be noted in the output of the report          
            $ErrorActionPreference = 'SilentlyContinue'
            $report = @()

            $sw = New-Object System.Diagnostics.Stopwatch
        }

        process
        {
            foreach ($c in $ComputerName)
            {
                for ($i = 0; $i -lt $Count; $i++) 
                {
                    $result = New-Object PSObject | Select-Object Server, Port, TypePort, Open, Notes, ResponseTime
                    $result.Server = $c
                    $result.Port = $Port
                    $result.TypePort = 'TCP'

                    if ($Tcp)
                    {
                        $tcpClient = New-Object System.Net.Sockets.TcpClient
                        $sw.Start()
                        try {
                            $connect = $tcpClient.BeginConnect($c, $Port, $null, $null)
                            $wait = $connect.AsyncWaitHandle.WaitOne($TcpTimeout, $false)
                        } catch {
                            $wait = $false
                        }

                        if (-not $wait)
                        {
                            try { $tcpClient.Close() } catch {}
                            $sw.Stop()
                            Write-Verbose "Connection Timeout to $c:$Port"

                            $result.Open = $false
                            $result.Notes = 'Connection to Port Timed Out'
                            $result.ResponseTime = $sw.ElapsedMilliseconds
                        }
                        else
                        {
                            try { [void]$tcpClient.EndConnect($connect); $tcpClient.Dispose() } catch {}
                            $sw.Stop()
                            $result.Open = $true
                        }

                        $result.ResponseTime = $sw.ElapsedMilliseconds
                    }
                    if ($Udp)
                    {
                        $udpClient = New-Object System.Net.Sockets.UdpClient
                        $udpClient.Client.ReceiveTimeout = $UdpTimeout

                        $a = New-Object System.Text.ASCIIEncoding
                        $byte = $a.GetBytes("$(Get-Date)")

                        $result.Server = $c
                        $result.Port = $Port
                        $result.TypePort = 'UDP'

                        Write-Verbose "Making UDP connection to remote server $c:$Port"
                        $sw.Start()
                        try {
                            $udpClient.Connect($c, $Port)
                            [void]$udpClient.Send($byte, $byte.Length)
                            $remoteEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                            $receiveBytes = $udpClient.Receive([ref]$remoteEndpoint)
                            $sw.Stop()
                            [string]$returnedData = $a.GetString($receiveBytes)
                            Write-Verbose 'UDP Response received'

                            $result.Open = $true
                            $result.Notes = $returnedData
                        }
                        catch
                        {
                            Write-Verbose "UDP receive failed or timed out for $c:$Port. Unable to verify open state."
                            $result.Open = $false
                            $result.Notes = 'Unable to verify if port is open or if host is unavailable.'
                        }
                        finally
                        {
                            try { $udpClient.Dispose() } catch {}
                            $result.ResponseTime = $sw.ElapsedMilliseconds
                        }
                    }

                    $sw.Reset()
                    $report += $result

                    Start-Sleep -Milliseconds $Delay
                }
            }
        }

        end
        {
            $report 
        }
    }

    Write-Verbose -Message "Script started at $(Get-Date)"

    $portListPath = Join-Path -Path $scriptRoot -ChildPath 'Ports.txt'
    $formatPath = Join-Path -Path $scriptRoot -ChildPath 'PortTest.format.ps1xml'
    
    $portsHashTable = @{}
    if (Test-Path -Path $portListPath -PathType Leaf)
    {        
        $ports = Import-Csv -Path $portListPath -Delimiter '|' -Header 'Port', 'Protocol', 'ServiceName', 'ServiceDescription' | Where-Object Protocol -eq tcp

        foreach ($item in $ports)
        {
            try
            {
                $portsHashTable[$item.Port] = ("{0}|{1}" -f $item.ServiceName, $item.ServiceDescription)
            }
            catch
            { 
            }
        }
    }
    
    if (Test-Path -Path $formatPath)
    {
        Update-FormatData -PrependPath $formatPath
    }

    $assignServiceWithPort = $true
    # Get the ScriptBlock for Test-Port defined above
    $sb = (Get-Command -Name Test-Port -ErrorAction SilentlyContinue).ScriptBlock
    if (-not $sb) {
        Throw "Failed to get the Test-Port scriptblock. Aborting."
    }

    # expand ports:
    # If -Port is specified, it may contain single ports, ports with protocol suffix (e.g. 53u/53t), or ranges (e.g. 0-1023 or 0-1023t)
    function Expand-PortSpecs {
        param([string[]]$Specs)

        $expanded = New-Object System.Collections.ArrayList

        foreach ($spec in $Specs) {
            if (-not $spec) { continue }
            $s = $spec.Trim()

            # match range: start-end with optional protocol suffix
            if ($s -match '^(?<start>\d{1,5})-(?<end>\d{1,5})(?<prot>[ut])?$') {
                $start = [int]$Matches.start
                $end = [int]$Matches.end
                $prot = $Matches.prot

                if ($start -gt $end) {
                    # swap
                    $tmp = $start; $start = $end; $end = $tmp
                }

                # clamp to 0..65535
                if ($start -lt 0) { $start = 0 }
                if ($end -gt 65535) { $end = 65535 }

                for ($p = $start; $p -le $end; $p++) {
                    $entry = $p.ToString()
                    if ($prot) { $entry += $prot }
                    [void]$expanded.Add($entry)
                }
            }
            # match single port with optional protocol suffix: e.g. 53u, 80t, 22
            elseif ($s -match '^(?<port>\d{1,5})(?<prot>[ut])?$') {
                $port = [int]$Matches.port
                if ($port -ge 0 -and $port -le 65535) {
                    [void]$expanded.Add($s)
                }
            }
            else {
                Write-Verbose "Ignoring invalid port spec: '$s'"
            }
        }

        return ,$expanded
    }

    $ports = if ($Port)
    {
        # Expand range-style entries and normalize to objects with Protocol property
        $rawExpanded = Expand-PortSpecs -Specs $Port
        $rawExpanded
    }
    else
    {
        # Build numeric sequence StartPort..EndPort
        if ($StartPort -lt 0) { $StartPort = 0 }
        if ($EndPort -gt 65535) { $EndPort = 65535 }
        ($StartPort..$EndPort) | ForEach-Object { $_.ToString() }
    }

    # now convert to psobjects with Protocol
    $portsToScan = $ports.Count
    $ports = foreach ($p in $ports)
    {
        if ($null -eq $p) { continue }
        [void]($p -match '(?<Port>\d{1,5})(?<Protocol>[ut]{1})?')
        $portNumber = [int]$Matches.Port
        $proto = if ($Matches.Protocol -eq 'u') { 'Udp' } elseif ($Matches.Protocol -eq 't') { 'Tcp' } else { 'Tcp' }

        # Create a custom object with numeric port and protocol
        [pscustomobject]@{
            Port = $portNumber
            Protocol = $proto
            Raw = $p
        }
    }

    # Prepare collection for all results (to allow export later)
    [System.Collections.ArrayList]$AllResults = @()
}

process
{

    Write-Verbose -Message "Test if host is reachable..."
    
    Write-Verbose -Message "Scanning range from $StartPort to $EndPort ($portsToScan Ports)"
    Write-Verbose -Message "Running with max $Threads threads"

    # Check if ComputerName is already an IPv4-Address, if not... try to resolve it
    $ipv4Address = $ComputerName -as [IPAddress]
	
    if (-not $ipv4Address)
    {
        # Get IP from Hostname (IPv4 only)
        try
        {
            $addressList = @(([System.Net.Dns]::GetHostEntry($ComputerName)).AddressList)
			
            foreach ($Address in $addressList)
            {
                if ($Address.AddressFamily -eq "InterNetwork") 
                {					
                    $ipv4Address = $Address.IPAddressToString 
                    break					
                }
            }					
        }
        catch
        { 
        }	# Can't get IPAddressList 					

        if (-not $ipv4Address)
        {
            throw "Could not get IPv4-Address for $ComputerName. Try to enter an IPv4-Address instead of the Hostname."
        }		
    }

    Write-Verbose -Message "Setting up RunspacePool..."

    $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $Host)
    $runspacePool.Open()
    [System.Collections.ArrayList]$jobs = @()

    Write-Verbose -Message "Setting up Jobs..."
    $i = 0
    
    #Set up job for each port
    foreach ($p in $ports)
    {
        $scriptParams = @{
            ComputerName = $ipv4Address
            Port         = $p.Port
        }
        if ($p.Protocol -eq 'Tcp')
        {
            $scriptParams.Add('Tcp', $true)
        }
        else
        {
            $scriptParams.Add('Udp', $true)
        }

        # Catch when trying to divide through zero
        try
        {
            $progressPercent = $i / $portsToScan * 100
            $i++
        } 
        catch
        { 
            $progressPercent = 100 
        }

        Write-Progress -Activity "Setting up jobs..." -Id 1 -Status "Current Port: $($p.Port) ($($p.Protocol))" -PercentComplete ($progressPercent)
        
        $job = [System.Management.Automation.PowerShell]::Create().AddScript($sb).AddParameters($scriptParams)
        $job.RunspacePool = $runspacePool
        
        $jobResult = [pscustomobject]@{
            RunNum = $p.Port - $StartPort
            Pipe   = $job
            Result = $job.BeginInvoke()
        }

        # Add job to collection
        [void]$jobs.Add($jobResult)
    }

    Write-Verbose -Message "Waiting for jobs to complete & starting to process results..."

    # Total jobs to calculate percent complete, because jobs are removed after they are processed
    $jobsTotal = $jobs.Count

    # Process results, while waiting for other jobs
    Do
    {
        # Get all jobs, which are completed
        $jobsToProcess = $jobs | Where-Object { $_.Result.IsCompleted }
  
        # If no jobs finished yet, wait 500 ms and try again
        if (-not $jobsToProcess)
        {
            Write-Verbose -Message "No jobs completed, wait 500ms..."

            Start-Sleep -Milliseconds 500
            continue
        }
        
        # Get jobs, which are not complete yet
        $jobsRemaining = ($jobs | Where-Object { $_.Result.IsCompleted -eq $false }).Count

        # Catch when trying to divide through zero
        try
        {            
            $progressPercent = 100 - $jobsRemaining / $jobsTotal * 100
        }
        catch
        {
            $progressPercent = 100
        }

        Write-Progress -Activity "Waiting for jobs to complete... ($($Threads - $($runspacePool.GetAvailableRunspaces())) of $Threads threads running)" -Id 1 -PercentComplete $progressPercent -Status "$jobsRemaining remaining..."
      
        Write-Verbose -Message "Processing $(if($null -eq $jobsToProcess.Count){"1"}else{$jobsToProcess.Count}) job(s)..."

        # Processing completed jobs
        foreach ($job in $jobsToProcess)
        {       
            # Get the result...     
            $jobResult = $job.Pipe.EndInvoke($job.Result)
            $job.Pipe.Dispose()

            # Remove job from collection
            $jobs.Remove($job)
            
            $result = @{
                PSTypeName   = 'PortScanResult'
                ComputerName = $ComputerName
                IPV4Address  = $ipv4Address
                Port         = $jobResult.Port
                Protocol     = $jobResult.TypePort
                Status       = $jobResult.Open
                ResponseTime = $jobResult.ResponseTime
                Notes        = $jobResult.Notes
            }
           
            if ($assignServiceWithPort)
            {
                $service = $portsHashTable."$($jobResult.Port)"
                if ($service)
                {
                    $service = $service.Split('|')
                    $result.Add('ServiceName', $Service[0])
                    $result.Add('ServiceDescription', $Service[1])
                }
            }
            
            if ($result.Status -or $PSCmdlet.ParameterSetName -eq 'Port')
            {
                $result.PSObject.TypeNames.Insert(0, "PortScanResult")
                $out = [pscustomobject]$result

                # add to collection for optional export
                [void]$AllResults.Add($out)

                # stream output to host
                $out
            }
        } 

    } While ($jobs.Count -gt 0)
    
    Write-Verbose -Message "Closing RunspacePool and free resources..."

    $runspacePool.Dispose()

    Write-Verbose -Message "Script finished at $(Get-Date)"
}

end
{
    # If OutputPath provided, export results to CSV
    if ($OutputPath)
    {
        try {
            $folder = Split-Path -Path $OutputPath -Parent
            if (-not (Test-Path -Path $folder)) {
                New-Item -Path $folder -ItemType Directory -Force | Out-Null
            }

            $AllResults | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            Write-Verbose "Exported results to $OutputPath"
            Write-Host "Exported results to $OutputPath"
        }
        catch {
            Write-Warning "Failed to export results to $OutputPath: $_"
        }
    }
}
