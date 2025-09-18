Import-Module Microsoft.Graph.Reports
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.Authentication

#intro
Write-Host "Checker script for BetterSecDefaults" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "This script checks for information needed for optional policies as part of the BetterSecDefaults script." -BackgroundColor DarkBlue -ForegroundColor White
Write-Host "You'll be shown any successful sign-ins for the last 14 days that match the following conditions:" -BackgroundColor DarkGreen -ForegroundColor White
Start-Sleep -Seconds 1
Write-Host "-Logins from outside USA" -BackgroundColor DarkYellow -ForegroundColor Black
Write-Host "-Logins from macOS systems" -BackgroundColor DarkYellow -ForegroundColor Black
Write-Host "-Logins from Linux systems" -BackgroundColor DarkYellow -ForegroundColor Black
start-sleep -Seconds 1

#connect to graph
Write-Host "CONNECTING TO AZURE/GRAPH" -BackgroundColor DarkBlue -ForegroundColor White
$TenantId = Read-Host "Enter Azure TenantID"

# NOTE: Added Reports.Read.All so we can read MFA registration details
# (AuditLog.Read.All is still needed for sign-in logs)
Connect-MgGraph -TenantId $TenantId -Scopes "AuditLog.Read.All","Reports.Read.All","UserAuthenticationMethod.Read.All","UserAuthenticationMethod.ReadWrite.All" -NoWelcome
Start-Sleep -Seconds 2

Write-Host "Checking for international logons. This will take up to 120 seconds..." -BackgroundColor DarkBlue -ForegroundColor White

# Get the date 14 days ago (UTC-ish format)
$date14DaysAgo = (Get-Date).AddDays(-14).ToString("yyyy-MM-ddTHH:mm:ssZ")

# International sign-ins (successful, not US/Unknown/blank)
$filter = "Status/ErrorCode eq 0 and (Location/CountryOrRegion ne 'US' and Location/CountryOrRegion ne 'Unknown' and Location/CountryOrRegion ne '') and CreatedDateTime ge $date14DaysAgo"
$recentSignIns = Get-MgAuditLogSignIn -Filter $filter -Top 30 | Select-Object UserPrincipalName, @{Name="Location";Expression={$_.Location.CountryOrRegion}}

if (!$recentSignIns) {
    Write-Host "No international sign-ins were found in the last 14 days!" -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 3
} else {
    $recentSignIns | Format-Table -AutoSize
    Write-Host "You appear to have international sign ins in the last 14 days..." -BackgroundColor DarkRed -ForegroundColor White
    Start-Sleep -Seconds 3
}

# macOS sign-ins
Write-Host "Checking for successful Mac/OSX sign-ins. This may take up to 120 seconds..." -BackgroundColor DarkBlue -ForegroundColor White
$date14DaysAgo = (Get-Date).AddDays(-14).ToString("yyyy-MM-ddTHH:mm:ssZ")
$filter = "Status/ErrorCode eq 0 and (DeviceDetail/OperatingSystem eq 'MacOs' or DeviceDetail/OperatingSystem eq 'MacOS') and CreatedDateTime ge $date14DaysAgo"
$recentMacSignIns = Get-MgAuditLogSignIn -Filter $filter -Top 30 | Select-Object UserPrincipalName, @{Name="OperatingSystem";Expression={$_.DeviceDetail.OperatingSystem}}

if (!$recentMacSignIns) {
    Write-Host "No Mac/OSX sign-ins were found in the last 14 days! " -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 3
} else {
    $recentMacSignIns | Format-Table -AutoSize
    Write-Host "You appear to have MAC sign-ins in the last 14 days..." -BackgroundColor DarkRed -ForegroundColor White
    Start-Sleep -Seconds 3
}

# Linux sign-ins
Write-Host "Checking for successful Linux sign-ins. This may take up to 120 seconds..." -BackgroundColor DarkBlue -ForegroundColor White
$date14DaysAgo = (Get-Date).AddDays(-14).ToString("yyyy-MM-ddTHH:mm:ssZ")
$filter = "Status/ErrorCode eq 0 and (DeviceDetail/OperatingSystem eq 'Linux') and CreatedDateTime ge $date14DaysAgo"
$recentLinuxSignIns = Get-MgAuditLogSignIn -Filter $filter -Top 30 | Select-Object UserPrincipalName, @{Name="OperatingSystem";Expression={$_.DeviceDetail.OperatingSystem}}

if (!$recentLinuxSignIns) {
    Write-Host "No Linux sign-ins were found in the last 14 days! " -BackgroundColor Green -ForegroundColor White
    Start-Sleep -Seconds 3
} else {
    $recentLinuxSignIns | Format-Table -AutoSize
    Write-Host "You appear to have Linux sign ins in the last 14 days. " -BackgroundColor DarkRed -ForegroundColor White
    Start-Sleep -Seconds 3
}


# Fetch users with MFA enabled
Write-Host "Checking for users with MFA enabled..." -BackgroundColor DarkBlue -ForegroundColor White

$usersWithMfa = @()
Get-MgUser -All | ForEach-Object {
    $user = $_
    $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
    if ($authMethods.Count -gt 1) {
        $usersWithMfa += [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            MFAState = "Enabled"
        }
    }
}

if (!$usersWithMfa) {
    Write-Host "No users with MFA enabled were found!" -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 3
} else {
    # Display the results
    $usersWithMfa | Format-Table -AutoSize
    Write-Host "The above users have MFA enabled..." -BackgroundColor DarkRed -ForegroundColor White
    Start-Sleep -Seconds 3
}
