<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Kieran OHearn
    LinkedIn        : linkedin.com/in/kieran-o-8a4a37180/
    GitHub          : github.com/kieran-3
    Date Created    : 3-24-2025
    Last Modified   : 3-24-2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 3-24-2025
    Tested By       : Kieran OHearn
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# Define the registry path
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"

# Define the registry key and value
$propertyName = "MaxSize"
$propertyValue = 0x8000  # 32768 in decimal

# Ensure the registry path exists
if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the registry value
Set-ItemProperty -Path $registryPath -Name $propertyName -Value $propertyValue -Type DWord

# Confirm the change
Write-Output "Registry value $propertyName set to $propertyValue at $registryPath"
