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
# Prompt for tenant ID
$TenantId = Read-Host "Enter Azure TenantID"
# Authenticate to Azure AD and Microsoft Graph
Connect-MgGraph -TenantId $TenantId -Scopes "AuditLog.Read.All" -NoWelcome
Start-Sleep -Seconds 2
Write-Host "Checking for international logons. This will take up to 120 seconds..." -BackgroundColor DarkBlue -ForegroundColor White
# Get the current date and the date 30 days ago
# Get the date 30 days ago
$date14DaysAgo = (Get-Date).AddDays(-14).ToString("yyyy-MM-ddTHH:mm:ssZ")

# Filter for sign-ins within the last 14 days
$filter = "Status/ErrorCode eq 0 and (Location/CountryOrRegion ne 'US' and Location/CountryOrRegion ne 'Unknown' and Location/CountryOrRegion ne '') and CreatedDateTime ge $date14DaysAgo"

# Select relevant properties from the filtered results
$recentSignIns = Get-MgAuditLogSignIn -Filter $filter -top 30 | Select-Object UserPrincipalName, @{Name="Location";Expression={$_.Location.CountryOrRegion}}

# Check if $recentSignIns is empty or null
if (!$recentSignIns) {
    Write-Host "No international sign-ins were found in the last 14 days!" -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 3
} else {
    # Display the results
    $recentSignIns | Format-Table -AutoSize
    Write-Host "You appear to have international sign ins in the last 14 days..." -BackgroundColor DarkRed -ForegroundColor White
    Start-Sleep -Seconds 3
}

# Fetch Mac Sign Ins
Write-Host "Checking for successful Mac/OSX sign-ins. This may take up to 120 seconds..." -BackgroundColor DarkBlue -ForegroundColor White

# Use filtering in the initial query to reduce the amount of data retrieved
# Calculate the date 14 days ago
$date14DaysAgo = (Get-Date).AddDays(-14).ToString("yyyy-MM-ddTHH:mm:ssZ")

# Efficient filter for sign-ins within the last 14 days
$filter = "Status/ErrorCode eq 0 and (DeviceDetail/OperatingSystem eq 'MacOs' or DeviceDetail/OperatingSystem eq 'MacOS') and CreatedDateTime ge $date14DaysAgo"
#$signIns = Get-MgAuditLogSignIn -Filter $filter -top 30 | Select-Object UserPrincipalName, @{Name="OperatingSystem";Expression={$_.DeviceDetail.OperatingSystem}}

# Select UserPrincipalName and OperatingSystem directly from the filtered results
$recentMacSignIns = Get-MgAuditLogSignIn -Filter $filter -top 30 | Select-Object UserPrincipalName, @{Name="OperatingSystem";Expression={$_.DeviceDetail.OperatingSystem}}

# Check if $recentMacSignIns is empty or null
if (!$recentMacSignIns) {
    Write-Host "No Mac/OSX sign-ins were found in the last 14 days! " -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 3
} else {
    # Display the results
    $recentMacSignIns | Format-Table -AutoSize
    Write-Host "You appear to have MAC sign-ins in the last 14 days..." -BackgroundColor DarkRed -ForegroundColor White
    Start-Sleep -Seconds 3
}

# Fetch Linux Sign Ins
Write-Host "Checking for successful Linux sign-ins. This may take up to 120 seconds..." -BackgroundColor DarkBlue -ForegroundColor White

# Calculate the date 14 days ago
$date14DaysAgo = (Get-Date).AddDays(-14).ToString("yyyy-MM-ddTHH:mm:ssZ")

# Use filtering in the initial query to reduce the amount of data retrieved
$filter = "Status/ErrorCode eq 0 and (DeviceDetail/OperatingSystem eq 'Linux') and CreatedDateTime ge $date14DaysAgo"
#$signIns = Get-MgAuditLogSignIn -Filter $filter -top 30 | Select-Object UserPrincipalName, @{Name="OperatingSystem";Expression={$_.DeviceDetail.OperatingSystem}}

# Select UserPrincipalName and OperatingSystem directly from the filtered results
$recentLinuxSignIns = Get-MgAuditLogSignIn -Filter $filter -top 30 | Select-Object UserPrincipalName, @{Name="OperatingSystem";Expression={$_.DeviceDetail.OperatingSystem}}

# Check if $recentLinuxSignIns is empty or null
if (!$recentLinuxSignIns) {
    Write-Host "No Linux sign-ins were found in the last 14 days! " -BackgroundColor Green -ForegroundColor White
    Start-Sleep -Seconds 3
} else {
    # Display the results
    $recentLinuxSignIns | Format-Table -AutoSize
    Write-Host "You appear to have Linux sign ins in the last 14 days. " -BackgroundColor DarkRed -ForegroundColor White
    Start-Sleep -Seconds 3
}
