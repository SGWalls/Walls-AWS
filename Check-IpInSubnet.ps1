function Test-IpInSubnet {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IpAddress,
        
        [Parameter(Mandatory = $true)]
        [string]$Subnet
    )
    
    # Split the subnet into IP and prefix
    $parts = $Subnet.Split('/')
    $subnetIp = $parts[0]
    $prefixLength = [int]$parts[1]
    
    # Convert IP addresses to integers for comparison
    $ipBytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)
    
    $subnetBytes = [System.Net.IPAddress]::Parse($subnetIp).GetAddressBytes()
    [Array]::Reverse($subnetBytes)
    $subnetInt = [System.BitConverter]::ToUInt32($subnetBytes, 0)
    
    # Calculate subnet mask
    $mask = (-1 -shl (32 - $prefixLength))
    
    # Check if IP is in subnet
    ($ipInt -band $mask) -eq ($subnetInt -band $mask)
}

function Find-SubnetMatch {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IpAddress,
        
        [Parameter(Mandatory = $true)]
        [string[]]$SubnetList
    )
    
    $matches = @()
    
    foreach ($subnet in $SubnetList) {
        if (Test-IpInSubnet -IpAddress $IpAddress -Subnet $subnet) {
            $matches += $subnet
        }
    }
    
    return $matches
}

# Example usage
$ipToCheck = $args[0]
if (-not $ipToCheck) {
    $ipToCheck = Read-Host "Enter IP address to check"
}

# Read subnet list from file or use hardcoded list
$subnetListFile = "subnets.txt"
if (Test-Path $subnetListFile) {
    $subnetList = Get-Content $subnetListFile
}
else {
    $subnetList = @(
        "150.222.51.160/27",
        "151.148.40.0/24",
        "159.248.224.0/21",
        "204.246.168.0/22",
        "3.4.12.1/32",
        "13.208.0.0/16",
        "13.248.75.0/24"
    )
}

$matchingSubnets = Find-SubnetMatch -IpAddress $ipToCheck -SubnetList $subnetList

if ($matchingSubnets.Count -gt 0) {
    Write-Host "IP $ipToCheck belongs to the following subnet(s):" -ForegroundColor Green
    $matchingSubnets | ForEach-Object { Write-Host "- $_" }
}
else {
    Write-Host "IP $ipToCheck does not belong to any subnet in the list." -ForegroundColor Yellow
}