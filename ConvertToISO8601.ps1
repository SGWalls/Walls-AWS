function Convert-ToISO8601 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Timestamp
    )
    
    # Parse the timestamp (format: YYYYMMDD HH:MM:SS)
    $year = $Timestamp.Substring(0, 4)
    $month = $Timestamp.Substring(4, 2)
    $day = $Timestamp.Substring(6, 2)
    $time = $Timestamp.Substring(9)
    
    # Create DateTime object
    $dateTime = [datetime]::ParseExact("$year-$month-$day $time", "yyyy-MM-dd HH:mm:ss", $null)
    
    # Return ISO 8601 format
    return $dateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
}

# Example usage:
# Convert-ToISO8601 "20250522 21:11:28"