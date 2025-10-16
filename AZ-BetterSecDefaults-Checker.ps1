Import-Module Microsoft.Graph.Reports
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.Authentication

# =========================
# ===== REPORT HELPERS =====
# =========================
function New-CardHtml {
    param(
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $ResultText,
        [Parameter(Mandatory)] [ValidateSet('ok','bad','info')] [string] $ResultState,
        [Parameter(Mandatory)] [string] $BodyHtml
    )
@"
<div class='card'>
  <div class='card-head'>
    <h3>$Title</h3>
    <span class='badge $ResultState'>$ResultText</span>
  </div>
  <div class='card-body'>
    $BodyHtml
  </div>
</div>
"@
}

function Convert-ObjectsToTableHtml {
    param(
        [Parameter(Mandatory)] [object[]] $InputObject
    )
    if (-not $InputObject -or $InputObject.Count -eq 0) { return "" }
    # ConvertTo-Html tends to be verbose; trim inline styles and keep a clean table
    $html = $InputObject | ConvertTo-Html -As Table -Fragment
    # Remove default ConvertTo-Html styles
    ($html -join "`n") -replace '<table>',"<table class='table'>" `
                       -replace '<th>','<th>' `
                       -replace '<td>','<td>'
}

function Build-ReportHtml {
    param(
        [string] $TenantId,
        [datetime] $SinceDate,
        [object[]] $IntlSignIns,
        [object[]] $MacSignIns,
        [object[]] $LinuxSignIns,
        [object[]] $LegacySignIns,
        [object[]] $LegacySummary,   # objects with Protocol and Count
        [object[]] $UsersWithMfa
    )

$generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss K')
$since = $SinceDate.ToString('yyyy-MM-dd')

# Cards: International
if ($IntlSignIns -and $IntlSignIns.Count -gt 0) {
    $intlBody = @"
<p><strong>You have $($IntlSignIns.Count) international sign-ins in the last 14 days consider excluding these users from the appropriate policy.</strong></p>
$(Convert-ObjectsToTableHtml $IntlSignIns)
"@
    $intlCard = New-CardHtml -Title "International Sign-ins (non-US)" -ResultText "Found" -ResultState bad -BodyHtml $intlBody
} else {
    $intlCard = New-CardHtml -Title "International Sign-ins (non-US)" -ResultText "None found" -ResultState ok -BodyHtml "<p>No international sign-ins since $since.</p>"
}

# Cards: macOS
if ($MacSignIns -and $MacSignIns.Count -gt 0) {
    $macBody = @"
<p><strong>You have $($MacSignIns.Count) macOS sign-ins in the last 14 days consider excluding these users from the appropriate policy.</strong></p>
$(Convert-ObjectsToTableHtml $MacSignIns)
"@
    $macCard = New-CardHtml -Title "macOS Sign-ins" -ResultText "Found" -ResultState bad -BodyHtml $macBody
} else {
    $macCard = New-CardHtml -Title "macOS Sign-ins" -ResultText "None found" -ResultState ok -BodyHtml "<p>No macOS sign-ins since $since.</p>"
}

# Cards: Linux
if ($LinuxSignIns -and $LinuxSignIns.Count -gt 0) {
    $linuxBody = @"
<p><strong>You have $($LinuxSignIns.Count) Linux sign-ins in the last 14 days consider excluding these users from the appropriate policy.</strong></p>
$(Convert-ObjectsToTableHtml $LinuxSignIns)
"@
    $linuxCard = New-CardHtml -Title "Linux Sign-ins" -ResultText "Found" -ResultState bad -BodyHtml $linuxBody
} else {
    $linuxCard = New-CardHtml -Title "Linux Sign-ins" -ResultText "None found" -ResultState ok -BodyHtml "<p>No Linux sign-ins since $since.</p>"
}

# Cards: Legacy Auth
if ($LegacySignIns -and $LegacySignIns.Count -gt 0) {
    $legacySummaryHtml = if ($LegacySummary -and $LegacySummary.Count -gt 0) {
        Convert-ObjectsToTableHtml $LegacySummary
    } else { "" }

    $legacyBody = @"
<p><strong>You have $($LegacySignIns.Count) legacy authentication sign-ins in the last 14 days consider excluding these users from the appropriate policy.</strong></p>
<h4>By Protocol</h4>
$legacySummaryHtml
<h4>Details</h4>
$(Convert-ObjectsToTableHtml $LegacySignIns)
"@
    $legacyCard = New-CardHtml -Title "Legacy Authentication Sign-ins" -ResultText "Found" -ResultState bad -BodyHtml $legacyBody
} else {
    $legacyCard = New-CardHtml -Title "Legacy Authentication Sign-ins" -ResultText "None found" -ResultState ok -BodyHtml "<p>No legacy authentication sign-ins since $since.</p>"
}

# Cards: Users with MFA enabled (informational — not sign-ins)
if ($UsersWithMfa -and $UsersWithMfa.Count -gt 0) {
    $mfaBody = @"
<p><strong>$($UsersWithMfa.Count) users have MFA enabled.</strong></p>
$(Convert-ObjectsToTableHtml $UsersWithMfa)
"@
    $mfaCard = New-CardHtml -Title "Users with MFA Enabled" -ResultText "$($UsersWithMfa.Count) users" -ResultState info -BodyHtml $mfaBody
} else {
    $mfaCard = New-CardHtml -Title "Users with MFA Enabled" -ResultText "0 users" -ResultState info -BodyHtml "<p>No users with MFA enabled were found.</p>"
}

@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BetterSecDefaults – Sign-in Review</title>
<style>
  :root{
    --bg:#0b1220; --card:#101a2b; --muted:#8aa0c6; --text:#e8eefb;
    --ok:#1f7a1f; --bad:#b6383b; --info:#375a9e; --border:#223251; --table:#0f1725;
  }
  *{box-sizing:border-box}
  body{margin:0;background: radial-gradient(1200px 600px at 10% -10%, #132036 0, transparent 60%),
                     radial-gradient(1000px 500px at 110% 10%, #1b2740 0, transparent 60%),
                     var(--bg); color:var(--text); font: 14px/1.45 system-ui,Segoe UI,Roboto,Inter,Apple Color Emoji,Segoe UI Emoji}
  header{padding:28px 24px 10px; border-bottom:1px solid var(--border)}
  header h1{margin:0 0 6px;font-size:24px;letter-spacing:.3px}
  header .meta{color:var(--muted)}
  .container{padding:20px 24px 40px}
  .grid{display:grid; grid-template-columns: repeat(auto-fit,minmax(360px,1fr)); gap:18px}
  .card{background:linear-gradient(180deg, #0f1a2d 0, #0d1630 100%); border:1px solid var(--border); border-radius:16px; box-shadow:0 6px 18px rgba(0,0,0,.35)}
  .card-head{display:flex; align-items:center; justify-content:space-between; padding:16px 16px 0}
  .card-head h3{margin:0; font-size:16px}
  .badge{border-radius:999px; padding:6px 10px; font-weight:700; font-size:12px; letter-spacing:.25px}
  .badge.ok{background:rgba(31,122,31,.18); color:#b6f2b6; border:1px solid rgba(31,122,31,.6)}
  .badge.bad{background:rgba(182,56,59,.16); color:#ffd6d7; border:1px solid rgba(182,56,59,.65)}
  .badge.info{background:rgba(55,90,158,.16); color:#cfe0ff; border:1px solid rgba(55,90,158,.65)}
  .card-body{padding:12px 16px 18px}
  .card-body p{margin:10px 0 14px; color:var(--text)}
  .card-body h4{margin:10px 0 8px; font-size:13px; color:var(--muted); text-transform:uppercase; letter-spacing:.4px}
  table.table {
    width:100%;
    max-width:100%;
    border-collapse:collapse;
    background:var(--table);
    border-radius:10px;
    overflow:hidden;
    table-layout: fixed;     /* keeps columns from stretching */
    word-wrap: break-word;
  }
  .card-body {
    padding:12px 16px 18px;
    overflow-x:auto;         /* adds scroll if still too wide */
  }
  table.table th, table.table td {
    padding:8px 10px;
    text-align:left;
    border-bottom:1px solid #1b2741;
    vertical-align:top;
    white-space:normal;      /* allows wrapping */
    word-break:break-word;   /* breaks long UPNs cleanly */
    font-size:13px;
  }
  table.table th {
    color:#b9c8e8;
    font-weight:700;
    font-size:12px;
    text-transform:uppercase;
    letter-spacing:.35px;
    background:#121b31
  }
  table.table tr:hover td {background:#0e1a31}
  footer{margin-top:16px; color:var(--muted); text-align:center}

</style>
</head>
<body>
<header>
  <h1>BetterSecDefaults Signin Review</h1>
  <div class="meta">Tenant: <strong>$TenantId</strong>  Since: <strong>$since</strong>  Generated: <strong>$generated</strong></div>
</header>
<div class="container">
  <div class="grid">
    $intlCard
    $macCard
    $linuxCard
    $legacyCard
    $mfaCard
  </div>
  <footer>Report generated by BetterSecDefaults checker.</footer>
</div>
</body>
</html>
"@
}

# ==============
# ===== MAIN ===
# ==============
# Intro
Write-Host "Checker script for BetterSecDefaults" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "This script checks for information needed for optional policies as part of the BetterSecDefaults script." -BackgroundColor DarkBlue -ForegroundColor White
Write-Host "You'll be shown any successful sign-ins for the last 14 days that match the following conditions:" -BackgroundColor DarkGreen -ForegroundColor White
Start-Sleep -Seconds 1
Write-Host "-Logins from outside USA" -BackgroundColor DarkYellow -ForegroundColor Black
Write-Host "-Logins from macOS systems" -BackgroundColor DarkYellow -ForegroundColor Black
Write-Host "-Logins from Linux systems" -BackgroundColor DarkYellow -ForegroundColor Black
Write-Host "-Logins from Legacy Auth Clients" -BackgroundColor DarkYellow -ForegroundColor Black
Write-Host "-Users with MFA Enabled" -BackgroundColor DarkYellow -ForegroundColor Black
Start-Sleep -Seconds 1

# Connect
Write-Host "CONNECTING TO AZURE/GRAPH" -BackgroundColor DarkBlue -ForegroundColor White
$TenantId = Read-Host "Enter Azure TenantID"
Connect-MgGraph -TenantId $TenantId -Scopes "AuditLog.Read.All","Reports.Read.All","UserAuthenticationMethod.Read.All","UserAuthenticationMethod.ReadWrite.All" -NoWelcome
Start-Sleep -Seconds 2

# Time window
$sinceDate = (Get-Date).AddDays(-14)
$date14DaysAgo = $sinceDate.ToString("yyyy-MM-ddTHH:mm:ssZ")

# ===========================
# International sign-ins
# ===========================
Write-Host "Checking for international logons..." -BackgroundColor DarkBlue -ForegroundColor White
$filterIntl = "Status/ErrorCode eq 0 and (Location/CountryOrRegion ne 'US' and Location/CountryOrRegion ne 'Unknown' and Location/CountryOrRegion ne '') and CreatedDateTime ge $date14DaysAgo"
$recentSignIns = Get-MgAuditLogSignIn -Filter $filterIntl -Top 200 |
    Select-Object UserPrincipalName, @{Name="Location";Expression={$_.Location.CountryOrRegion}}, CreatedDateTime

if (!$recentSignIns) {
    Write-Host "No international sign-ins were found in the last 14 days!" -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 1
} else {
    $recentSignIns | Format-Table -AutoSize
    Write-Host "You appear to have international sign ins in the last 14 days..." -BackgroundColor DarkRed -ForegroundColor White
    Start-Sleep -Seconds 1
}

# ===========================
# macOS sign-ins
# ===========================
Write-Host "Checking for successful Mac/OSX sign-ins..." -BackgroundColor DarkBlue -ForegroundColor White
$filterMac = "Status/ErrorCode eq 0 and (DeviceDetail/OperatingSystem eq 'MacOs' or DeviceDetail/OperatingSystem eq 'MacOS') and CreatedDateTime ge $date14DaysAgo"
$recentMacSignIns = Get-MgAuditLogSignIn -Filter $filterMac -Top 200 |
    Select-Object UserPrincipalName, @{Name="OperatingSystem";Expression={$_.DeviceDetail.OperatingSystem}}, CreatedDateTime

if (!$recentMacSignIns) {
    Write-Host "No Mac/OSX sign-ins were found in the last 14 days! " -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 1
} else {
    $recentMacSignIns | Format-Table -AutoSize
    Write-Host "You appear to have MAC sign-ins in the last 14 days..." -BackgroundColor DarkRed -ForegroundColor White
    Start-Sleep -Seconds 1
}

# ===========================
# Linux sign-ins
# ===========================
Write-Host "Checking for successful Linux sign-ins..." -BackgroundColor DarkBlue -ForegroundColor White
$filterLinux = "Status/ErrorCode eq 0 and (DeviceDetail/OperatingSystem eq 'Linux') and CreatedDateTime ge $date14DaysAgo"
$recentLinuxSignIns = Get-MgAuditLogSignIn -Filter $filterLinux -Top 200 |
    Select-Object UserPrincipalName, @{Name="OperatingSystem";Expression={$_.DeviceDetail.OperatingSystem}}, CreatedDateTime

if (!$recentLinuxSignIns) {
    Write-Host "No Linux sign-ins were found in the last 14 days! " -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 1
} else {
    $recentLinuxSignIns | Format-Table -AutoSize
    Write-Host "You appear to have Linux sign ins in the last 14 days. " -BackgroundColor DarkRed -ForegroundColor White
    Start-Sleep -Seconds 1
}

# ===========================
# Users with MFA enabled (informational)
# ===========================
Write-Host "Checking for users with MFA enabled..." -BackgroundColor DarkBlue -ForegroundColor White
$usersWithMfa = @()
Get-MgUser -All | ForEach-Object {
    $user = $_
    try {
        $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop
        if ($authMethods.Count -gt 1) {
            $usersWithMfa += [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                MFAState          = "Enabled"
            }
        }
    } catch {
        # Ignore users we cannot enumerate methods for
    }
}
if (!$usersWithMfa) {
    Write-Host "No users with MFA enabled were found!" -BackgroundColor DarkBlue -ForegroundColor White
} else {
    $usersWithMfa | Format-Table -AutoSize
    Write-Host "The above users have MFA enabled..." -BackgroundColor DarkBlue -ForegroundColor White
}

# ===========================
# Legacy Authentication sign-ins (client-side filtering to catch SMTP, etc.)
# ===========================
Write-Host "Checking for legacy authentication sign-ins..." -BackgroundColor DarkBlue -ForegroundColor White
# Broad fetch (then filter locally). Increase -Top or use -All for bigger tenants.
$allSignIns = Get-MgAuditLogSignIn -Filter "Status/ErrorCode eq 0 and CreatedDateTime ge $date14DaysAgo" -Top 999

$legacyApps = @(
    'Other clients',
    'IMAP4',
    'POP3',
    'Authenticated SMTP',
    'Autodiscover',
    'MAPI over HTTP',
    'Exchange ActiveSync'
)

$legacyAuthSignIns = $allSignIns | Where-Object { $legacyApps -contains $_.ClientAppUsed } |
    Select-Object UserPrincipalName, ClientAppUsed, AppDisplayName, CreatedDateTime

if (!$legacyAuthSignIns) {
    Write-Host "No legacy authentication sign-ins were found in the last 14 days!" -BackgroundColor DarkGreen -ForegroundColor White
} else {
    $legacyAuthSignIns | Format-Table -AutoSize
    Write-Host "Legacy authentication sign-ins detected (including Authenticated SMTP)." -BackgroundColor DarkRed -ForegroundColor White
}

# Build legacy summary (counts by protocol)
$legacySummary = @()
if ($legacyAuthSignIns) {
    $legacySummary = $legacyAuthSignIns |
        Group-Object ClientAppUsed |
        Sort-Object Count -Descending |
        ForEach-Object {
            [PSCustomObject]@{ Protocol = $_.Name; Count = $_.Count }
        }
}

# ===========================
# Assemble HTML report
# ===========================
$reportHtml = Build-ReportHtml -TenantId $TenantId `
    -SinceDate $sinceDate `
    -IntlSignIns $recentSignIns `
    -MacSignIns $recentMacSignIns `
    -LinuxSignIns $recentLinuxSignIns `
    -LegacySignIns $legacyAuthSignIns `
    -LegacySummary $legacySummary `
    -UsersWithMfa $usersWithMfa

$reportPath = Join-Path (Get-Location) "BetterSecDefaults-Report.html"
$reportHtml | Set-Content -Path $reportPath -Encoding UTF8

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " HTML report written to: $reportPath" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Start-Process $reportPath

