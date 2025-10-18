# One-liner: list AD computer objects and their OS fields
Import-Module ActiveDirectory; Get-ADComputer -Filter * -Properties OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack |
  Select-Object Name,OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack |
  Sort-Object Name

