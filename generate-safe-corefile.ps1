# ================================
#  Generate Windows-safe CoreDNS zones
#  This script MUST be executed in  Windows PowerShell 5 (the built‑in Windows version).
#  PowerShell 7+ removed Get-WmiObject, so running this script in pwsh 7 will fail.
#  Use the built-in Windows PowerShell (powershell.exe), not pwsh.exe.
# ================================

# 1. Get local hostname
$Hostname = $env:COMPUTERNAME

# 2. Get the primary DNS suffix
#    Win32_ComputerSystem.Domain returns WORKGROUP on non-domain machines, so ignore it
$Domain = (Get-WmiObject Win32_ComputerSystem).Domain
if ($Domain -eq $Hostname -or $Domain -eq "WORKGROUP") {
    $Domain = ""
}

# 3. Get connection-specific DNS suffixes (often more accurate than Domain)
$NICSuffixes = Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled -eq $true -and $_.DNSDomain -ne $null } |
    Select-Object -ExpandProperty DNSDomain -Unique

# Prefer NIC DNS suffix if available
if ($NICSuffixes -and $NICSuffixes.Count -gt 0) {
    $Domain = $NICSuffixes[0]
}

# 4. Build the zone list
$Zones = @(
    "localhost",
    "local",
    "localdomain",
    $Hostname
)

if ($Domain -ne "") {
    # Quote the domain to avoid CoreDNS parsing issues
    $Zones += "`"$Domain`""
}

$Zones += @(
    "in-addr.arpa",
    "ip6.arpa",
    "wpad",
    "msftncsi.com"
)

# 5. Output Corefile snippet
Write-Host ""
Write-Host "### Windows-safe non-CarbolicAcid zones ###"
Write-Host ""

# Join zones into a single line
$ZoneLine = ($Zones -join " ")

Write-Host "$ZoneLine {"
Write-Host "`t# Forward these system-critical queries to a non-local resolver"
Write-Host "`t# Example: forward . 1.1.1.1 8.8.8.8"
Write-Host "`t# Or any upstream you prefer"
Write-Host "}"
Write-Host ""
Write-Host ". {"
Write-Host "`tcarbolicacid {"
Write-Host "`t`t# Your CarbolicAcid configuration"
Write-Host "`t}"
Write-Host "`t# Other plugins"
Write-Host "}"
Write-Host ""