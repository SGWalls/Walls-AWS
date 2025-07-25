function Write-HelloWorld {
    <#
    .SYNOPSIS
        A simple Hello World function in PowerShell.
    
    .DESCRIPTION
        This function prints "Hello, World!" to the console when called.
        
    .EXAMPLE
        Write-HelloWorld
        Outputs: Hello, World!
        
    .EXAMPLE
        Write-HelloWorld -Name "John"
        Outputs: Hello, John!
    
    .PARAMETER Name
        Optional. The name to greet. If not provided, defaults to "World".
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$Name = "World"
    )
    
    Write-Output "Hello, $Name!"
}

# Example usage:
# Write-HelloWorld
# Write-HelloWorld -Name "PowerShell User"