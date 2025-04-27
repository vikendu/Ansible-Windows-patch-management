param ()

#region Helper Functions

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp [$Severity] $Message"

    switch ($Severity) {
        "Info"    { Write-Host $LogEntry -ForegroundColor Green }
        "Warning" { Write-Host $LogEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $LogEntry -ForegroundColor Red; break } # Stop on error
    }
    # Could also write to a file, event log, etc.
}

#endregion Helper Functions

# Main Script Logic
try {
    # Check if the script is running with administrator privileges
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log -Severity "Error" -Message "Script must be run as administrator."
        exit 1
    }

    # Define the registry key path
    $regKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    # Check if the registry key exists, create it if it doesn't
    if (-not (Test-Path -Path $regKeyPath)) {
        Write-Log -Severity "Info" -Message "Creating registry key: $regKeyPath"
        New-Item -Path $regKeyPath -Force | Out-Null
    }

    # Set AUOptions to 1 to disable automatic updates
    $AUOptions = 1
    Write-Log -Severity "Info" -Message "Setting AUOptions to: $AUOptions (Never check for updates)"
    Set-ItemProperty -Path $regKeyPath -Name "AUOptions" -Value $AUOptions -Force

    Write-Log -Severity "Info" -Message "Automatic Updates policy configured successfully to never check for updates."

} catch {
    Write-Log -Severity "Error" -Message "An error occurred: $($_.Exception.Message)"
    exit 1
}
