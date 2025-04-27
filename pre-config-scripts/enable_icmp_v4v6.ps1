if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run with Administrator privileges."
    exit 1
}

# --- Configure Inbound Rule for ICMPv4 ---
Write-Host "Configuring inbound rule for ICMPv4 (Echo Request)..."
$v4RuleName = "Allow ICMPv4-In"
$v4DisplayName = "Allow Inbound ICMPv4 Echo Request"

# Check if the rule already exists
if (Get-NetFirewallRule -Name $v4RuleName -ErrorAction SilentlyContinue) {
    Write-Host "ICMPv4 inbound rule '$v4DisplayName' already exists. Skipping creation."
} else {
    try {
        New-NetFirewallRule -Name $v4RuleName -DisplayName $v4DisplayName -Protocol ICMPv4 -Direction Inbound -Action Allow -Enabled True
        Write-Host "Successfully created inbound rule '$v4DisplayName'."
    } catch {
        Write-Error "Error creating ICMPv4 inbound rule: $($_.Exception.Message)"
    }
}

# --- Configure Inbound Rule for ICMPv6 ---
Write-Host "Configuring inbound rule for ICMPv6 (Echo Request)..."
$v6RuleName = "Allow ICMPv6-In"
$v6DisplayName = "Allow Inbound ICMPv6 Echo Request"

# Check if the rule already exists
if (Get-NetFirewallRule -Name $v6RuleName -ErrorAction SilentlyContinue) {
    Write-Host "ICMPv6 inbound rule '$v6DisplayName' already exists. Skipping creation."
} else {
    try {
        New-NetFirewallRule -Name $v6RuleName -DisplayName $v6DisplayName -Protocol ICMPv6 -Direction Inbound -Action Allow -Enabled True
        Write-Host "Successfully created inbound rule '$v6DisplayName'."
    } catch {
        Write-Error "Error creating ICMPv6 inbound rule: $($_.Exception.Message)"
    }
}

Write-Host "Script completed."