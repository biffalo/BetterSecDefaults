################!#################################################################################################################
###############!##################################################################################################################
##############!#INTRO#############################################################################################################
###############!##################################################################################################################
#################!################################################################################################################
# Script Name: Azure BetterSecDefaults
# Description: Creates a set of conditional access policies that will provide improved security over Microsofts "Security Defaults".
# This script is primarily for less mature orgs that are perhaps still using Microsofts "Security Defaults" 
# or only have very basic conditional access policies in place. 
# Author - https://github.com/biffalo/
# Credits - SecOps-Institute for TOR IP List //// X4BNet for the VPN IP List
Write-Host "  ____       _   _            ____            ____        __             _ _       " -BackgroundColor DarkBlue -ForegroundColor Black
Write-Host " | __ )  ___| |_| |_ ___ _ __/ ___|  ___  ___|  _ \  ___ / _| __ _ _   _| | |_ ___ " -BackgroundColor DarkBlue -ForegroundColor Black
Write-Host " |  _ \ / _ \ __| __/ _ \ '__\___ \ / _ \/ __| | | |/ _ \ |_ / _` | | | | | __/ __|" -BackgroundColor DarkBlue -ForegroundColor Black
Write-Host " | |_) |  __/ |_| ||  __/ |   ___) |  __/ (__| |_| |  __/  _| (_| | |_| | | |_\__ \" -BackgroundColor DarkBlue -ForegroundColor Black
Write-Host " |____/ \___|\__|\__\___|_|  |____/ \___|\___|____/ \___|_|  \__,_|\__,_|_|\__|___/" -BackgroundColor DarkBlue -ForegroundColor Black
Write-Host "                                                                                   " -BackgroundColor DarkBlue -ForegroundColor Black
Write-Host "This script creates 7 conditional access policies." -BackgroundColor DarkBlue -ForegroundColor White
Write-Host "MFA for All Apps with trusted location/hybrid joined devices excluded" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "Block outside of USA (excludes global admin)" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "Deny logon from device types Mac/Osx (excludes global admin)" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "Deny logon from device types Linux (excludes global admin)" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "Block Legacy Auth Except for Trusted Locations" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "Blocks logins from known VPN Providers/TOR Exit Nodes (excludes global admin) " -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "Sign In Risk Policy (medium and high) (excludes global admin)(excludes trust locations)" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "Be sure to have TENANTID, GLOBAL ADMIN CREDS, and TRUSTED IPs IN CIDR FORMAT" -BackgroundColor DarkYellow -ForegroundColor Black

############!#####################################################################################################################
##########!#######################################################################################################################
###########!Connect##################################################################################################
#############!####################################################################################################################
##############!###################################################################################################################
Write-Host "CONNECTING TO AZURE/GRAPH" -BackgroundColor DarkBlue -ForegroundColor White
# Import Other Modules
Import-Module Microsoft.Graph.Reports
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.Authentication
# Prompt for tenant ID
$TenantId = Read-Host "Enter Azure TenantID"
# Authenticate to Azure AD and Microsoft Graph
Connect-MgGraph -TenantId $TenantId -Scopes "User.Read.All, Policy.ReadWrite.ConditionalAccess, Directory.Read.All, Policy.Read.All, RoleManagement.Read.All" -NoWelcome
##########!#######################################################################################################################
###########!######################################################################################################################
##########!#Lic Check##################################################################################################
###########!######################################################################################################################
############!#####################################################################################################################
Write-Host "CHECKING FOR AzureAD/Entra P2 LIC" -BackgroundColor DarkBlue -ForegroundColor White

# Check for AzureAD/Entra Premium P2 license
$licenses = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/subscribedSkus"
$p2License = $licenses.value | Where-Object { $_.skuPartNumber -eq "AAD_PREMIUM_P2" }

if (-not $p2License) {
    Write-Host "You have the wrong license type. AzureAD/Entra P2 license required. Exiting script." -BackgroundColor DarkRed -ForegroundColor White
    exit
} else {
    Write-Host "AzureAD/Entra P2 license is present! Continuing..." -BackgroundColor DarkGreen -ForegroundColor White
}

Write-Host "Caching existing Conditional Access policies and Global Administrator role..." -BackgroundColor DarkBlue -ForegroundColor White
$ExistingCAPolicies = Get-MgIdentityConditionalAccessPolicy -All
$GlobalAdminRoleIds = Get-MgRoleManagementDirectoryRoleDefinition -All |
    Where-Object { $_.DisplayName -eq "Global Administrator" } |
    Select-Object -ExpandProperty Id

function Refresh-ConditionalAccessPolicyCache {
    $script:ExistingCAPolicies = Get-MgIdentityConditionalAccessPolicy -All
}

function Wait-NamedLocationAvailable {
    param(
        [Parameter(Mandatory)]
        [string]$NamedLocationId,

        [int]$MaxAttempts = 12,

        [int]$DelaySeconds = 5
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $NamedLocationId -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            if ($attempt -eq $MaxAttempts) {
                return $false
            }

            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function Wait-ConditionalAccessPolicyAvailable {
    param(
        [string]$PolicyId,

        [Parameter(Mandatory)]
        [string]$DisplayName,

        [int]$MaxAttempts = 12,

        [int]$DelaySeconds = 5
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            if (-not [string]::IsNullOrWhiteSpace($PolicyId)) {
                $policy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $PolicyId -ErrorAction Stop
            }
            else {
                $policy = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop |
                    Where-Object { $_.DisplayName -eq $DisplayName } |
                    Select-Object -First 1
            }

            if ($policy) {
                return $true
            }
        }
        catch {
            if ($attempt -eq $MaxAttempts) {
                return $false
            }
        }

        Start-Sleep -Seconds $DelaySeconds
    }

    return $false
}

##########!#######################################################################################################################
###########!######################################################################################################################
##########!#Check for Sec Defaults################################################################################################
###########!######################################################################################################################
############!#####################################################################################################################
# Check for Sec Defaults - Disable if Enabled
Write-Host "Checking if 'Security Defaults' is enabled..." -BackgroundColor DarkBlue -ForegroundColor White
$getSD = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy

if ($getSD.IsEnabled -eq $true) {
    Write-Host "'Security Defaults' is enabled. Disabling it now...." -BackgroundColor DarkRed -ForegroundColor White
    $params = @{
        IsEnabled = $false
    }
    
    Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params
} 
else {
    Write-Host "'Security Defaults' is disabled. Continuing..." -BackgroundColor DarkGreen -ForegroundColor White
}
#!################################################################################################################################
##!###############################################################################################################################
###!####MFA FOR ALL CAP###########################################################################################################
####!#############################################################################################################################
#####!############################################################################################################################
Write-Host "POLICY - MFA FOR ALL" -BackgroundColor DarkBlue -ForegroundColor White

# Named Location Name
$locationName = "Trusted"

# Helper: Get named location reliably (server-side filter + explicit select)
function Get-TrustedNamedLocation {
    param([string]$Name)

    $loc = Get-MgIdentityConditionalAccessNamedLocation `
        -Filter "displayName eq '$Name'" `
        -Property "id,displayName" `
        -All |
        Select-Object -First 1

    # Some SDK shapes place fields in AdditionalProperties
    if ($loc -and [string]::IsNullOrWhiteSpace($loc.Id) -and $loc.AdditionalProperties) {
        $maybeId = $loc.AdditionalProperties["id"]
        if (-not [string]::IsNullOrWhiteSpace($maybeId)) {
            $loc | Add-Member -NotePropertyName Id -NotePropertyValue $maybeId -Force
        }
    }

    return $loc
}

# Check if the named location already exists
$existingNamedLocation = Get-TrustedNamedLocation -Name $locationName

if ($null -ne $existingNamedLocation) {
    Write-Host "Named location 'Trusted' already exists with ID: $($existingNamedLocation.Id)" -BackgroundColor DarkBlue -ForegroundColor White

    # Verify the location is retrievable
    try {
        Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $existingNamedLocation.Id -ErrorAction Stop | Out-Null
        Write-Host "Verified named location 'Trusted' is accessible." -BackgroundColor DarkGreen -ForegroundColor White
    }
    catch {
        Write-Host "WARNING: Named location exists but cannot be retrieved. Recreating..." -BackgroundColor DarkYellow -ForegroundColor Black
        $existingNamedLocation = $null
    }
}

if ($null -eq $existingNamedLocation) {
    # Get WAN IP from User only when the trusted location must be created
    $ipRanges = Read-Host "Enter Trusted Location IP Address in CIDR format."

    # Define the named location
    $namedLocationParams = @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        displayName  = "Trusted"
        isTrusted    = $true
        ipRanges     = @(
            @{
                "@odata.type" = "#microsoft.graph.iPv4CidrRange"
                cidrAddress  = $ipRanges
            }
        )
    }

    # Create the named location
    try {
        New-MgIdentityConditionalAccessNamedLocation -BodyParameter $namedLocationParams -ErrorAction Stop | Out-Null
        Write-Host "Named location 'Trusted' created successfully." -BackgroundColor DarkGreen -ForegroundColor White
    }
    catch {
        Write-Host "ERROR: Failed to create named location: $($_.Exception.Message)" -BackgroundColor DarkRed -ForegroundColor White
    }
}


# Check if Conditional Access Policy already exists
$existingPolicies = $ExistingCAPolicies |
    Where-Object { $_.DisplayName -eq "MFA for All" }

if ($null -ne $existingPolicies) {
    Write-Host "Conditional Access Policy 'MFA for All' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
}
else {

    # Define Conditional Access Policy - excludes ALL trusted named locations
    $conditionalAccessPolicy = @{
        displayName = "MFA for All"
        state       = "enabled"
        conditions  = @{
            users        = @{
                includeUsers = @("all")
            }
            applications = @{
                includeApplications = @("all")
            }
            locations    = @{
                includeLocations = @("All")
                excludeLocations = @("AllTrusted")
            }
        }
        grantControls = @{
            operator        = "OR"
            builtInControls = @("mfa", "domainJoinedDevice")
        }
    }

    try {
        $createdMfaPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $conditionalAccessPolicy -ErrorAction Stop
        if (Wait-ConditionalAccessPolicyAvailable -PolicyId $createdMfaPolicy.Id -DisplayName "MFA for All") {
            Write-Host "Conditional Access Policy 'MFA for All' created successfully." -BackgroundColor DarkGreen -ForegroundColor White
        }
        else {
            Write-Host "WARNING: Graph accepted 'MFA for All', but it is not visible in policy lookups yet." -BackgroundColor DarkYellow -ForegroundColor Black
        }
        Refresh-ConditionalAccessPolicyCache
    }
    catch {
        Write-Host "ERROR: Failed to create Conditional Access Policy: $($_.Exception.Message)" -BackgroundColor DarkRed -ForegroundColor White
    }
}
#!################################################################################################################################
#!################################################################################################################################
##!##### BLOCK OUTSIDE USA CAP — AUTO MODE ########################################################################################
###!##############################################################################################################################
####!#############################################################################################################################

Write-Host "AUTO: Checking Block Outside USA policy…" -BackgroundColor DarkBlue -ForegroundColor White

# ======================================================================
# Variables
# ======================================================================
$locationName = "Outside USA"
$policyName   = "Block Outside USA"

# List of all country codes except the United States
$countryCodes = @(
    "AD","AE","AF","AG","AI","AL","AM","AO","AQ","AR","AS","AT","AU","AW","AX","AZ","BA","BB","BD","BE","BF","BG","BH","BI","BJ","BL","BM","BN","BO","BQ","BR","BS","BT",
    "BV","BW","BY","BZ","CA","CC","CD","CF","CG","CH","CI","CK","CL","CM","CN","CO","CR","CU","CV","CW","CX","CY","CZ","DE","DJ","DK","DM","DO","DZ","EC","EE","EG","EH",
    "ER","ES","ET","FI","FJ","FK","FM","FO","FR","GA","GB","GD","GE","GF","GG","GH","GI","GL","GM","GN","GP","GQ","GR","GS","GT","GU","GW","GY","HK","HM","HN","HR","HT",
    "HU","ID","IE","IL","IM","IN","IO","IQ","IR","IS","IT","JE","JM","JO","JP","KE","KG","KH","KI","KM","KN","KP","KR","KW","KY","KZ","LA","LB","LC","LI","LK","LR","LS",
    "LT","LU","LV","LY","MA","MC","MD","ME","MF","MG","MH","MK","ML","MM","MN","MO","MP","MQ","MR","MS","MT","MU","MV","MW","MX","MY","MZ","NA","NC","NE","NF","NG","NI",
    "NL","NO","NP","NR","NU","NZ","OM","PA","PE","PF","PG","PH","PK","PL","PM","PN","PR","PS","PT","PW","PY","QA","RE","RO","RS","RU","RW","SA","SB","SC","SD","SE","SG",
    "SH","SI","SJ","SK","SL","SM","SN","SO","SR","SS","ST","SV","SX","SY","SZ","TC","TD","TF","TG","TH","TJ","TK","TL","TM","TN","TO","TR","TT","TV","TW","TZ","UA","UG",
    "UM","UY","UZ","VA","VC","VE","VG","VI","VN","VU","WF","WS","YE","YT","ZA","ZM","ZW"
)

# ======================================================================
# Named Location — Check / Create
# ======================================================================
$existingLocation = Get-MgIdentityConditionalAccessNamedLocation -All |
                    Where-Object { $_.DisplayName -eq $locationName } |
                    Select-Object -First 1

if (-not $existingLocation) {
    Write-Host "Creating named location '$locationName'…" -BackgroundColor DarkBlue -ForegroundColor White

    $params = @{
        "@odata.type"                       = "#microsoft.graph.countryNamedLocation"
        DisplayName                          = $locationName
        CountriesAndRegions                  = $countryCodes
        IncludeUnknownCountriesAndRegions    = $false
    }

    try {
        $existingLocation = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params -ErrorAction Stop
        Write-Host "Named location created with ID: $($existingLocation.Id)" -BackgroundColor DarkGreen -ForegroundColor White
    }
    catch {
        Write-Host "ERROR: Failed to create named location '$locationName': $($_.Exception.Message)" -BackgroundColor DarkRed -ForegroundColor White
        $existingLocation = $null
    }
}
else {
    Write-Host "Named location '$locationName' already exists with ID: $($existingLocation.Id)" -BackgroundColor DarkGreen -ForegroundColor White
}

# ======================================================================
# Conditional Access Policy — Check / Create
# ======================================================================
$existingPolicy = $ExistingCAPolicies |
                  Where-Object { $_.DisplayName -eq $policyName }

if (-not $existingPolicy) {
    # Verify we have a valid ID
    if ([string]::IsNullOrWhiteSpace($existingLocation.Id)) {
        Write-Host "ERROR: Named Location ID is empty. Cannot create policy." -BackgroundColor DarkRed -ForegroundColor White
    }
    elseif (-not (Wait-NamedLocationAvailable -NamedLocationId $existingLocation.Id)) {
        Write-Host "ERROR: Named location '$locationName' was created, but Graph is not returning it yet. Skipping '$policyName' for this run." -BackgroundColor DarkRed -ForegroundColor White
    }
    else {
        Write-Host "Creating Conditional Access policy '$policyName'…" -BackgroundColor DarkBlue -ForegroundColor White

        $adminRolesIds = $GlobalAdminRoleIds

        $policy = @{
            displayName = $policyName
            state       = "enabled"
            conditions  = @{
                users = @{
                    includeUsers = @("All")
                    excludeRoles = $adminRolesIds
                }
                locations = @{
                    includeLocations = @($existingLocation.Id)
                }
                clientAppTypes = @("All")
                applications    = @{
                    includeApplications = @("All")
                }
            }
            grantControls = @{
                operator        = "OR"
                builtInControls = @("block")
            }
        }

        $policyCreated = $false
        $maxPolicyCreateAttempts = 18
        $policyCreateDelaySeconds = 10

        for ($attempt = 1; $attempt -le $maxPolicyCreateAttempts; $attempt++) {
            try {
                $createdOutsidePolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policy -ErrorAction Stop

                if (Wait-ConditionalAccessPolicyAvailable -PolicyId $createdOutsidePolicy.Id -DisplayName $policyName) {
                    Write-Host "Conditional Access policy '$policyName' created successfully." -BackgroundColor DarkGreen -ForegroundColor White
                }
                else {
                    Write-Host "WARNING: Graph accepted '$policyName', but it is not visible in policy lookups yet." -BackgroundColor DarkYellow -ForegroundColor Black
                }

                Refresh-ConditionalAccessPolicyCache
                $policyCreated = $true
                break
            }
            catch {
                $message = $_.Exception.Message
                $namedLocationNotReady = $message -match "1040|NamedLocation.*does not exist"

                if ($namedLocationNotReady -and $attempt -lt $maxPolicyCreateAttempts) {
                    Write-Host ("Named location '$locationName' is not ready for policy validation yet. Retrying in {0} seconds ({1}/{2})..." -f $policyCreateDelaySeconds, $attempt, $maxPolicyCreateAttempts) -BackgroundColor DarkYellow -ForegroundColor Black
                    Start-Sleep -Seconds $policyCreateDelaySeconds
                    continue
                }

                Write-Host "ERROR: Failed to create Conditional Access policy '$policyName': $message" -BackgroundColor DarkRed -ForegroundColor White
                break
            }
        }

        if (-not $policyCreated) {
            Write-Host "Conditional Access policy '$policyName' was not created in this run." -BackgroundColor DarkRed -ForegroundColor White
        }
    }
}
else {
    Write-Host "Conditional Access policy '$policyName' already exists. Skipping." -BackgroundColor DarkGreen -ForegroundColor White
}

Write-Host "Block Outside USA — Completed" -BackgroundColor DarkBlue -ForegroundColor White


#######!##########################################################################################################################
###########!######################################################################################################################
####!### BLOCK MACOS CAP — AUTO MODE ############################################################################################
#####!############################################################################################################################
######!###########################################################################################################################

Write-Host "AUTO: Checking Block MacOS Sign-Ins policy…" -BackgroundColor DarkBlue -ForegroundColor White

$policyName = "Block MAC OS"

# ======================================================================
# Check for existing policy
# ======================================================================
$existingPolicy = $ExistingCAPolicies |
                  Where-Object { $_.DisplayName -eq $policyName }

if ($existingPolicy) {
    Write-Host "Conditional Access policy '$policyName' already exists. Skipping." -BackgroundColor DarkGreen -ForegroundColor White
}
else {
    # ======================================================================
    # Create the policy (only if missing)
    # ======================================================================

    Write-Host "Creating Conditional Access policy '$policyName'…" -BackgroundColor DarkBlue -ForegroundColor White

    $adminRolesIds = $GlobalAdminRoleIds

    $conditions = @{
        users = @{
            includeUsers = @("All")
            excludeRoles = $adminRolesIds
        }
        clientAppTypes = @("All")
        platforms = @{
            includePlatforms = @("macOS")
        }
        applications = @{
            includeApplications = @("All")
        }
        locations = @{
            includeLocations = @("All")
            excludeLocations = @("AllTrusted")
        }
    }

    $grantControls = @{
        operator        = "OR"
        builtInControls = @("block")
    }

    $policy = @{
        displayName   = $policyName
        state         = "enabled"
        conditions    = $conditions
        grantControls = $grantControls
    }

    try {
        New-MgIdentityConditionalAccessPolicy -BodyParameter $policy -ErrorAction Stop | Out-Null
        Write-Host "Conditional Access policy '$policyName' created successfully." -BackgroundColor DarkGreen -ForegroundColor White
        Refresh-ConditionalAccessPolicyCache
    }
    catch {
        Write-Host "ERROR: Failed to create Conditional Access policy '$policyName': $($_.Exception.Message)" -BackgroundColor DarkRed -ForegroundColor White
    }
}

#!################################################################################################################################
#!################################################################################################################################
#!###### BLOCK LINUX OS CAP — AUTO MODE ##########################################################################################
#!################################################################################################################################
#!################################################################################################################################

Write-Host "AUTO: Checking Block Linux Sign-Ins policy…" -BackgroundColor DarkBlue -ForegroundColor White

$policyName = "Block Linux OS"

# ======================================================================
# Check for existing policy
# ======================================================================
$existingPolicy = $ExistingCAPolicies |
                  Where-Object { $_.DisplayName -eq $policyName }

if ($existingPolicy) {
    Write-Host "Conditional Access policy '$policyName' already exists. Skipping." -BackgroundColor DarkGreen -ForegroundColor White
}
else {
    # ======================================================================
    # Create the policy (only if missing)
    # ======================================================================

    Write-Host "Creating Conditional Access policy '$policyName'…" -BackgroundColor DarkBlue -ForegroundColor White

    $adminRolesIds = $GlobalAdminRoleIds

    $params = @{
        displayName = $policyName
        state       = "enabled"
        conditions  = @{
            applications = @{
                includeApplications = @("All")
            }
            users = @{
                includeUsers  = @("All")
                excludeRoles  = $adminRolesIds
            }
            platforms = @{
                includePlatforms = @("Linux")
            }
            locations = @{
                includeLocations = @("All")
                excludeLocations = @("AllTrusted")
            }
        }
        grantControls = @{
            operator        = "OR"
            builtInControls = @("block")
        }
    }

    try {
        New-MgIdentityConditionalAccessPolicy -BodyParameter $params -ErrorAction Stop | Out-Null
        Write-Host "Conditional Access policy '$policyName' created successfully." -BackgroundColor DarkGreen -ForegroundColor White
        Refresh-ConditionalAccessPolicyCache
    }
    catch {
        Write-Host "ERROR: Failed to create Conditional Access policy '$policyName': $($_.Exception.Message)" -BackgroundColor DarkRed -ForegroundColor White
    }
}
#!################################################################################################################################
#!################################################################################################################################
#!######BLOCK LEGACY AUTH CAP######################################################################################################
#!################################################################################################################################
#!################################################################################################################################
Write-Host "Auto- Block Legacy Authentication" -BackgroundColor DarkBlue -ForegroundColor White


$policyName = "Block Legacy Auth"

# Define the Conditional Access policy body
$params = @{
    displayName = $policyName
    state       = "enabled"
    conditions  = @{
        users = @{
            includeUsers = @("all")
        }
        clientAppTypes = @("ExchangeActiveSync","Other")
        applications   = @{
            includeApplications = @("all")
        }
        locations = @{
            includeLocations = @("All")
            excludeLocations = @("AllTrusted")
        }
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("block")
    }
}

# Check if the policy already exists
$existingPolicy = $ExistingCAPolicies | Where-Object { $_.DisplayName -eq $policyName }

if ($null -ne $existingPolicy) {
    Write-Host "Conditional Access Policy '$policyName' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
} else {
    try {
        New-MgIdentityConditionalAccessPolicy -BodyParameter $params -ErrorAction Stop | Out-Null
        Write-Host "Conditional Access Policy '$policyName' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
        Refresh-ConditionalAccessPolicyCache
    }
    catch {
        Write-Host "ERROR: Failed to create Conditional Access Policy '$policyName': $($_.Exception.Message)" -BackgroundColor DarkRed -ForegroundColor White
    }
}

##########!##################################################################
#########!###################################################################
########!#######Get Bad IPs and Split Due to AZ Limits#######################
############!################################################################
#############!###############################################################
Write-Host "POLICY - BLOCK BAD IPs" -BackgroundColor DarkBlue -ForegroundColor White
$existingBadRepPolicy = $ExistingCAPolicies |
    Where-Object { $_.DisplayName -eq "BadRep IP Block" }

if ($null -ne $existingBadRepPolicy) {
    Write-Host "Conditional Access Policy 'BadRep IP Block' already exists - skipping BadRep location and policy creation." -BackgroundColor DarkBlue -ForegroundColor White
}
else {
    Write-Host "Conditional Access Policy 'BadRep IP Block' not found. Continuing..." -BackgroundColor DarkGreen -ForegroundColor White
    Write-Host "Getting Bad IP Lists (VPN + TOR)" -BackgroundColor DarkBlue -ForegroundColor White

# -----------------------------------------------------------------------------
# 1. Download and prepare source lists
# -----------------------------------------------------------------------------
$outputDir = "C:\temp"
if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# VPN list from X4BNet
$fileUrlVpn = "https://github.com/X4BNet/lists_vpn/raw/main/output/vpn/ipv4.txt"
$tempVpn = Join-Path $outputDir "vpn_ipv4.txt"
Invoke-WebRequest -Uri $fileUrlVpn -OutFile $tempVpn -UseBasicParsing

# TOR exit nodes
$fileUrlTor = "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst"
$tempTor = Join-Path $outputDir "tor_exit_nodes.txt"
Invoke-WebRequest -Uri $fileUrlTor -OutFile $tempTor -UseBasicParsing

# Append /32 to TOR entries (normalize format)
(Get-Content $tempTor | ForEach-Object { "$_/32" }) | Set-Content $tempTor -Encoding ASCII

# -----------------------------------------------------------------------------
# 2. Helper: chunked named-location creation
# -----------------------------------------------------------------------------
function New-ChunkedNamedLocation {
    param(
        [string]$DisplayName,
        [string]$FilePath,
        [int]$ChunkSize = 800
    )

    Write-Host "Processing $DisplayName from $FilePath ..." -BackgroundColor DarkBlue -ForegroundColor White

    if (-not (Test-Path $FilePath)) {
        Write-Host "File not found: $FilePath" -BackgroundColor DarkRed -ForegroundColor White
        return @()
    }

    $allIPs = Get-Content -Path $FilePath | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' }
    if ($allIPs.Count -eq 0) {
        Write-Host "No valid IPs found in $FilePath." -BackgroundColor DarkYellow -ForegroundColor Black
        return @()
    }

    $chunks = foreach ($i in 0..([Math]::Floor(($allIPs.Count - 1) / $ChunkSize))) {
        $start = $i * $ChunkSize
        $end = [Math]::Min($start + $ChunkSize - 1, $allIPs.Count - 1)
        ,($allIPs[$start..$end])
    }

    $createdIds = @()
    $part = 1
    foreach ($chunk in $chunks) {
        $chunkName = "$DisplayName-Part$part"

        $existing = Get-MgIdentityConditionalAccessNamedLocation -All |
            Where-Object { $_.DisplayName -eq $chunkName } |
            Select-Object -First 1
        if ($null -ne $existing) {
            # Verify the location is still valid
            try {
                Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $existing.Id -ErrorAction Stop | Out-Null
                Write-Host ("Named location '{0}' already exists and is valid - skipping." -f $chunkName) -BackgroundColor DarkBlue -ForegroundColor White
                $createdIds += $existing.Id
                $part++
                continue
            }
            catch {
                Write-Host ("WARNING: Named location '{0}' exists but is invalid. Recreating..." -f $chunkName) -BackgroundColor DarkYellow -ForegroundColor Black
                $existing = $null
            }
        }

        if ($null -eq $existing) {
            $ipArray = foreach ($ip in $chunk) {
                @{
                    "@odata.type" = "#microsoft.graph.iPv4CidrRange"
                    CidrAddress   = $ip
                }
            }

            $params = @{
                "@odata.type" = "#microsoft.graph.ipNamedLocation"
                DisplayName   = $chunkName
                IsTrusted     = $false
                IpRanges      = $ipArray
            }

            try {
                $created = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params -ErrorAction Stop
                $countText = "$($chunk.Count) IPs"
                Write-Host ("Created named location '{0}' ({1}) with ID: {2}" -f $chunkName, $countText, $created.Id) -BackgroundColor DarkGreen -ForegroundColor White
                
                # Verify the ID is not empty
                if (-not [string]::IsNullOrWhiteSpace($created.Id)) {
                    if (Wait-NamedLocationAvailable -NamedLocationId $created.Id) {
                        $createdIds += $created.Id
                    }
                    else {
                        Write-Host ("WARNING: Created location '{0}', but Graph is not returning it yet. It will be excluded from this run." -f $chunkName) -BackgroundColor DarkYellow -ForegroundColor Black
                    }
                }
                else {
                    Write-Host ("WARNING: Created location '{0}' but ID is empty!" -f $chunkName) -BackgroundColor DarkYellow -ForegroundColor Black
                }
            }
            catch {
                Write-Host ("Failed to create '{0}': {1}" -f $chunkName, $_.Exception.Message) -BackgroundColor DarkRed -ForegroundColor White
            }

        }
        
        $part++
    }

    return $createdIds
}

# -----------------------------------------------------------------------------
# 3. Create named locations for each list
# -----------------------------------------------------------------------------
$BadRep1_Locations = New-ChunkedNamedLocation -DisplayName "BadRep1" -FilePath $tempVpn
$BadRep3_Locations = New-ChunkedNamedLocation -DisplayName "BadRep3" -FilePath $tempTor

# Clean up temporary files
Remove-Item -Path $tempVpn, $tempTor -Force -ErrorAction SilentlyContinue

# -----------------------------------------------------------------------------
# 4. Create the Conditional Access Policy
# -----------------------------------------------------------------------------
Write-Host "Creating BadRep IP Block Conditional Access Policy..." -BackgroundColor DarkBlue -ForegroundColor White

# Combine all IDs and filter out any empty/null values
$AllBadRepIDs = @()
$AllBadRepIDs += $BadRep1_Locations | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$AllBadRepIDs += $BadRep3_Locations | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

Write-Host "Total valid named location IDs collected: $($AllBadRepIDs.Count)" -BackgroundColor DarkBlue -ForegroundColor White

if ($AllBadRepIDs.Count -eq 0) {
    Write-Host "No BadRep named locations found - skipping policy creation." -BackgroundColor DarkYellow -ForegroundColor Black
}
else {
    # Verify all collected IDs are still valid before creating policy
    Write-Host "Verifying all named location IDs are valid..." -BackgroundColor DarkBlue -ForegroundColor White
    $validIDs = @()
    foreach ($id in $AllBadRepIDs) {
        if (Wait-NamedLocationAvailable -NamedLocationId $id) {
            $validIDs += $id
        }
        else {
            Write-Host "WARNING: Named location ID $id is invalid and will be excluded from policy." -BackgroundColor DarkYellow -ForegroundColor Black
        }
    }
    
    Write-Host "Verified $($validIDs.Count) valid named location IDs." -BackgroundColor DarkGreen -ForegroundColor White
    
    if ($validIDs.Count -eq 0) {
        Write-Host "No valid named location IDs found - skipping policy creation." -BackgroundColor DarkYellow -ForegroundColor Black
    }
    else {
        $repblockparams = @{
            displayName = "BadRep IP Block"
            state       = "enabled"
            conditions  = @{
                applications = @{
                    includeApplications = @("All")
                }
                users = @{
                    includeUsers  = @("all")
                    excludeRoles  = $GlobalAdminRoleIds
                }
                locations = @{
                    includeLocations = $validIDs
                }
            }
            grantControls = @{
                operator        = "OR"
                builtInControls = @("block")
            }
        }

        try {
            New-MgIdentityConditionalAccessPolicy -BodyParameter $repblockparams -ErrorAction Stop | Out-Null
            Write-Host "Conditional Access Policy 'BadRep IP Block' created successfully." -BackgroundColor DarkGreen -ForegroundColor White
            Refresh-ConditionalAccessPolicyCache
        }
        catch {
            Write-Host "Failed to create 'BadRep IP Block' policy: $($_.Exception.Message)" -BackgroundColor DarkRed -ForegroundColor White
        }
    }
}
}
##############################!###################################################################################################
##############################!###################################################################################################
###########################!#########Create Sign-in Risk Block CAP################################################################
############################!#####################################################################################################
##############################!###################################################################################################
Write-Host "Creating Sign-In Risk Block Policy" -BackgroundColor DarkBlue -ForegroundColor White

# Get Global Administrator role ID
$AdminRolesIds = $GlobalAdminRoleIds

# Create the Conditional Access Policy
$conditions = @{
    Users = @{
        IncludeUsers = @("all")
        ExcludeRoles = $AdminRolesIds
    }
    Applications = @{
        IncludeApplications = @("all")
    }
    Locations = @{
        IncludeLocations = @("All")
        ExcludeLocations = @("AllTrusted")
    }
    SignInRiskLevels = @("medium", "high")
}

$controls = @{
    Operator = "OR"
    BuiltInControls = @("block")
}

$policyName = "Sign-In Risk Block"

$policyExists = $ExistingCAPolicies | Where-Object { $_.displayName -eq $policyName }

if ($null -ne $policyExists) {
    Write-Host "Conditional Access Policy 'Sign-In Risk Block' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
} 
else {
    try {
        New-MgIdentityConditionalAccessPolicy -DisplayName $policyName -State "Enabled" -Conditions $conditions -GrantControls $controls -ErrorAction Stop | Out-Null
        Write-Host "Conditional Access Policy 'Sign-In Risk Block' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
        Refresh-ConditionalAccessPolicyCache
    }
    catch {
        Write-Host "ERROR: Failed to create Conditional Access Policy 'Sign-In Risk Block': $($_.Exception.Message)" -BackgroundColor DarkRed -ForegroundColor White
    }
}

#############################!#########################################################
########################!##############################################################
###!###########Show Results#!###########################################################
############################!##########################################################
##############################!########################################################
$caps = Get-MgIdentityConditionalAccessPolicy -All | Select DisplayName, CreatedDateTime, State
Write-Host "The Following Conditional Access Policies Were Created or Already Exist:" -BackgroundColor DarkBlue -ForegroundColor White
$caps | Format-Table -AutoSize | Out-Host
Write-Host "Now disconnecting from AzureAD/Graph" -BackgroundColor DarkBlue -ForegroundColor White

#################################!#####################################################
################################!######################################################
##########!######Disconnect###########################################################
##################################!####################################################
###################################!###################################################
Disconnect-MgGraph | Out-Null
