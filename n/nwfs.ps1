# One-liner: list AD computer objects and their OS fields
Import-Module ActiveDirectory; Get-ADComputer -Filter * -Properties OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack |
  Select-Object Name,OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack |
  Sort-Object Name


  # Get current domain
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$root = "LDAP://$($domain.Name)"

# Search for all computer objects
$searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$root)
$searcher.Filter = "(objectCategory=computer)"
$searcher.PageSize = 1000  # For large domains
$searcher.PropertiesToLoad.AddRange(@("name","operatingSystem","operatingSystemVersion"))

$computers = $searcher.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Properties["name"] | Select-Object -First 1
        OperatingSystem = $_.Properties["operatingSystem"] | Select-Object -First 1
        OSVersion = $_.Properties["operatingSystemVersion"] | Select-Object -First 1
    }
}

$computers | Format-Table -AutoSize


$dns = if($env:USERDNSDOMAIN){ $env:USERDNSDOMAIN } else { (Get-CimInstance Win32_ComputerSystem).Domain }; Get-ChildItem -Path "\\$dns\SYSVOL" -Filter '*.bat' -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime
