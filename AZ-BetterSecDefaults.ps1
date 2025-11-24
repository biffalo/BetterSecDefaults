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
Write-Host "This script creates up to 6 conditional access policies." -BackgroundColor DarkBlue -ForegroundColor White
Write-Host "MFA for All Apps with trusted location/hybrid joined devices excluded" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "OPTIONAL! Block outside of USA (excludes global admin)" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "OPTIONAL! Deny logon from device types Mac/Osx (excludes global admin)" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "OPTIONAL! Deny logon from device types Linux (excludes global admin)" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "Block Legacy Auth Except for Trusted Locations" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "Blocks logins from known VPN Providers/TOR Exit Nodes (excludes global admin) " -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "Sign In Risk Policy (medium and high) (excludes global admin)" -BackgroundColor DarkGreen -ForegroundColor White
Write-Host "Be sure to have TENANTID, GLOBAL ADMIN CREDS, and TRUSTED IPs IN CIDR FORMAT" -BackgroundColor DarkYellow -ForegroundColor Black
Start-Sleep -Seconds 3
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
Start-Sleep -Seconds 2
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
    Start-Sleep -Seconds 1
    exit
} else {
    Write-Host "AzureAD/Entra P2 license is present! Continuing..." -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 1
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
    Start-Sleep -Seconds 1
    $params = @{
        IsEnabled = $false
    }
    
    Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params
} 
else {
    Write-Host "'Security Defaults' is disabled. Continuing..." -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 1
}

#!################################################################################################################################
##!###############################################################################################################################
###!####MFA FOR ALL CAP###########################################################################################################
####!#############################################################################################################################
#####!############################################################################################################################
Write-Host "POLICY - MFA FOR ALL" -BackgroundColor DarkBlue -ForegroundColor White

# Get WAN IP from User
$ipRanges = Read-Host "Enter Trusted Location IP Address in CIDR format."

# Check if the named location "Trusted" already exists
$locationName = "Trusted"
$existingNamedLocation = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq $locationName }

if ($null -ne $existingNamedLocation) {
    Write-Host "Named location 'Trusted' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
} else {
    # Define the named location policy
    $namedLocationParams = @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        displayName = "Trusted"
        isTrusted = $true
        ipRanges = @(@{ 
            "@odata.type" = "#microsoft.graph.iPv4CidrRange"
            cidrAddress = $ipRanges 
        })
    }

    # Create the named location policy
    $existingNamedLocation = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $namedLocationParams
    Write-Host "Named location 'Trusted' created successfully with ID: $($existingNamedLocation.Id)" -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 2
}

# Verify we have a valid ID
if ([string]::IsNullOrWhiteSpace($existingNamedLocation.Id)) {
    Write-Host "ERROR: Failed to get Named Location ID. Cannot create policy." -BackgroundColor DarkRed -ForegroundColor White
    Write-Host "Attempting to retrieve existing location..." -BackgroundColor DarkYellow -ForegroundColor Black
    $existingNamedLocation = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq $locationName }
    if ($null -eq $existingNamedLocation) {
        Write-Host "CRITICAL: Cannot find Trusted named location. Skipping MFA policy creation." -BackgroundColor DarkRed -ForegroundColor White
        Start-Sleep -Seconds 2
    }
}

# Only create policy if we have a valid named location ID
if ($null -ne $existingNamedLocation -and -not [string]::IsNullOrWhiteSpace($existingNamedLocation.Id)) {
    # Check if the Conditional Access Policy "MFA for All" already exists
    $existingPolicies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq "MFA for All" }

    if ($null -ne $existingPolicies) {
        Write-Host "Conditional Access Policy 'MFA for All' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
        Start-Sleep -Seconds 1
    } 
    else {
        # Create the Conditional Access Policy
        $conditionalAccessPolicy = @{
            displayName = "MFA for All"
            state = "enabled"
            conditions = @{
                users = @{
                    includeUsers = @("all")
                }
                applications = @{
                    includeApplications = @("all")
                }
                locations = @{
                    includeLocations = @("All")
                    excludeLocations = @($existingNamedLocation.Id)
                }
            }
            grantControls = @{
                operator = "OR"
                builtInControls = @("mfa", "domainJoinedDevice")
            }
        }

        # Create using the cmdlet instead of Invoke-MgGraphRequest
        New-MgIdentityConditionalAccessPolicy -BodyParameter $conditionalAccessPolicy
        Write-Host "Conditional Access Policy 'MFA for All' created successfully." -BackgroundColor DarkGreen -ForegroundColor White
        Start-Sleep -Seconds 1
    }
}

#!################################################################################################################################
#!################################################################################################################################
##!##### BLOCK OUTSIDE USA CAP — AUTO MODE ########################################################################################
###!##############################################################################################################################
####!#############################################################################################################################

Write-Host "AUTO: Checking Block Outside USA policy…" -BackgroundColor DarkBlue -ForegroundColor White
Start-Sleep -Seconds 1

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
$existingLocation = Get-MgIdentityConditionalAccessNamedLocation |
                    Where-Object { $_.DisplayName -eq $locationName }

if (-not $existingLocation) {
    Write-Host "Creating named location '$locationName'…" -BackgroundColor DarkBlue -ForegroundColor White

    $params = @{
        "@odata.type"                       = "#microsoft.graph.countryNamedLocation"
        DisplayName                          = $locationName
        CountriesAndRegions                  = $countryCodes
        IncludeUnknownCountriesAndRegions    = $false
    }

    $existingLocation = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
    
    Write-Host "Named location created with ID: $($existingLocation.Id)" -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 2
}
else {
    Write-Host "Named location '$locationName' already exists with ID: $($existingLocation.Id)" -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 1
}

# ======================================================================
# Conditional Access Policy — Check / Create
# ======================================================================
$existingPolicy = Get-MgIdentityConditionalAccessPolicy |
                  Where-Object { $_.DisplayName -eq $policyName }

if (-not $existingPolicy) {
    # Verify we have a valid ID
    if ([string]::IsNullOrWhiteSpace($existingLocation.Id)) {
        Write-Host "ERROR: Named Location ID is empty. Cannot create policy." -BackgroundColor DarkRed -ForegroundColor White
        Start-Sleep -Seconds 2
    }
    else {
        Write-Host "Creating Conditional Access policy '$policyName'…" -BackgroundColor DarkBlue -ForegroundColor White

        $adminRolesIds = Get-MgRoleManagementDirectoryRoleDefinition |
                         Where-Object { $_.DisplayName -like "*Global Administrator*" } |
                         Select-Object -ExpandProperty Id

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

        New-MgIdentityConditionalAccessPolicy -BodyParameter $policy

        Write-Host "Conditional Access policy created." -BackgroundColor DarkGreen -ForegroundColor White
        Start-Sleep -Seconds 1
    }
}
else {
    Write-Host "Conditional Access policy '$policyName' already exists. Skipping." -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 1
}

Write-Host "Block Outside USA — Completed" -BackgroundColor DarkBlue -ForegroundColor White
Start-Sleep -Seconds 1


#######!##########################################################################################################################
###########!######################################################################################################################
####!### BLOCK MACOS CAP — AUTO MODE ############################################################################################
#####!############################################################################################################################
######!###########################################################################################################################

Write-Host "AUTO: Checking Block MacOS Sign-Ins policy…" -BackgroundColor DarkBlue -ForegroundColor White
Start-Sleep -Seconds 1

$policyName = "Block MAC OS"

# ======================================================================
# Check for existing policy
# ======================================================================
$existingPolicy = Get-MgIdentityConditionalAccessPolicy |
                  Where-Object { $_.DisplayName -eq $policyName }

if ($existingPolicy) {
    Write-Host "Conditional Access policy '$policyName' already exists. Skipping." -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 1
}
else {
    # ======================================================================
    # Create the policy (only if missing)
    # ======================================================================

    Write-Host "Creating Conditional Access policy '$policyName'…" -BackgroundColor DarkBlue -ForegroundColor White

    $adminRolesIds = Get-MgRoleManagementDirectoryRoleDefinition |
                     Where-Object { $_.DisplayName -like "*Global Administrator*" } |
                     Select-Object -ExpandProperty Id

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
    }

    $grantControls = @{
        operator        = "OR"
        builtInControls = @("block")
    }

    $policy = @{
        displayName  = $policyName
        state        = "enabled"
        conditions   = $conditions
        grantControls = $grantControls
    }

    New-MgIdentityConditionalAccessPolicy -BodyParameter $policy

    Write-Host "Conditional Access policy '$policyName' created successfully." -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 1
}


#!################################################################################################################################
#!################################################################################################################################
#!###### BLOCK LINUX OS CAP — AUTO MODE ##########################################################################################
#!################################################################################################################################
#!################################################################################################################################

Write-Host "AUTO: Checking Block Linux Sign-Ins policy…" -BackgroundColor DarkBlue -ForegroundColor White
Start-Sleep -Seconds 1

$policyName = "Block Linux OS"

# ======================================================================
# Check for existing policy
# ======================================================================
$existingPolicy = Get-MgIdentityConditionalAccessPolicy |
                  Where-Object { $_.DisplayName -eq $policyName }

if ($existingPolicy) {
    Write-Host "Conditional Access policy '$policyName' already exists. Skipping." -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 1
}
else {
    # ======================================================================
    # Create the policy (only if missing)
    # ======================================================================

    Write-Host "Creating Conditional Access policy '$policyName'…" -BackgroundColor DarkBlue -ForegroundColor White

    $adminRolesIds = Get-MgRoleManagementDirectoryRoleDefinition |
                     Where-Object { $_.DisplayName -like "*Global Administrator*" } |
                     Select-Object -ExpandProperty Id

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
        }
        grantControls = @{
            operator        = "OR"
            builtInControls = @("block")
        }
    }

    New-MgIdentityConditionalAccessPolicy -BodyParameter $params

    Write-Host "Conditional Access policy '$policyName' created successfully." -BackgroundColor DarkGreen -ForegroundColor White
    Start-Sleep -Seconds 1
}

#!################################################################################################################################
#!################################################################################################################################
#!######BLOCK LEGACY AUTH CAP######################################################################################################
#!################################################################################################################################
#!################################################################################################################################
Write-Host "OPTIONAL POLICY! Block Legacy Authentication" -BackgroundColor DarkBlue -ForegroundColor White
Write-Host "This policy blocks Exchange ActiveSync and other legacy clients. Only create if you have confirmed legacy auth usage!" -BackgroundColor DarkYellow -ForegroundColor Black
Start-Sleep -Seconds 1

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
$existingPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq $policyName }

if ($null -ne $existingPolicy) {
    Write-Host "Conditional Access Policy '$policyName' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
} else {
    New-MgIdentityConditionalAccessPolicy -BodyParameter $params
    Write-Host "Conditional Access Policy '$policyName' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
}

##########!##################################################################
#########!###################################################################
########!#######Get Bad IPs and Split Due to AZ Limits#######################
############!################################################################
#############!###############################################################
Write-Host "POLICY - BLOCK BAD IPs" -BackgroundColor DarkBlue -ForegroundColor White
Write-Host "Getting Bad IP Lists (VPN + TOR)" -BackgroundColor DarkBlue -ForegroundColor White
Start-Sleep -Seconds 2

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

    $chunks = @()
    for ($i = 0; $i -lt $allIPs.Count; $i += $ChunkSize) {
        $chunks += ,($allIPs[$i..([Math]::Min($i + $ChunkSize - 1, $allIPs.Count - 1))])
    }

    $createdIds = @()
    $part = 1
    foreach ($chunk in $chunks) {
        $chunkName = "$DisplayName-Part$part"

        $existing = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq $chunkName }
        if ($null -ne $existing) {
            Write-Host ("Named location '{0}' already exists - skipping." -f $chunkName) -BackgroundColor DarkBlue -ForegroundColor White
            $createdIds += $existing.Id
            $part++
            continue
        }

        $ipArray = @()
        foreach ($ip in $chunk) {
            $ipArray += @{
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
            $created = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
            $countText = "$($chunk.Count) IPs"
            Write-Host ("Created named location '{0}' ({1}) with ID: {2}" -f $chunkName, $countText, $created.Id) -BackgroundColor DarkGreen -ForegroundColor White
            
            # Verify the ID is not empty
            if (-not [string]::IsNullOrWhiteSpace($created.Id)) {
                $createdIds += $created.Id
            }
            else {
                Write-Host ("WARNING: Created location '{0}' but ID is empty!" -f $chunkName) -BackgroundColor DarkYellow -ForegroundColor Black
            }
        }
        catch {
            Write-Host ("Failed to create '{0}': {1}" -f $chunkName, $_.Exception.Message) -BackgroundColor DarkRed -ForegroundColor White
        }

        $part++
        Start-Sleep -Seconds 2
    }

    return $createdIds
}

# -----------------------------------------------------------------------------
# 3. Create named locations for each list
# -----------------------------------------------------------------------------
$BadRep1_Locations = New-ChunkedNamedLocation -DisplayName "BadRep1" -FilePath $tempVpn
$BadRep2_Locations = New-ChunkedNamedLocation -DisplayName "BadRep2" -FilePath $tempVpn
$BadRep3_Locations = New-ChunkedNamedLocation -DisplayName "BadRep3" -FilePath $tempTor

# Clean up temporary files
Remove-Item -Path (Join-Path $outputDir "*.txt") -Force -ErrorAction SilentlyContinue

# -----------------------------------------------------------------------------
# 4. Create the Conditional Access Policy
# -----------------------------------------------------------------------------
Write-Host "Creating BadRep IP Block Conditional Access Policy..." -BackgroundColor DarkBlue -ForegroundColor White

# Combine all IDs and filter out any empty/null values
$AllBadRepIDs = @()
$AllBadRepIDs += $BadRep1_Locations | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$AllBadRepIDs += $BadRep2_Locations | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$AllBadRepIDs += $BadRep3_Locations | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

Write-Host "Total valid named location IDs collected: $($AllBadRepIDs.Count)" -BackgroundColor DarkBlue -ForegroundColor White

if ($AllBadRepIDs.Count -eq 0) {
    Write-Host "No BadRep named locations found - skipping policy creation." -BackgroundColor DarkYellow -ForegroundColor Black
}
else {
    $AdminRolesIds = Get-MgRoleManagementDirectoryRoleDefinition |
        Where-Object { $_.DisplayName -like '*Global Administrator*' } |
        Select-Object -ExpandProperty Id

    $repblockparams = @{
        displayName = "BadRep IP Block"
        state       = "enabled"
        conditions  = @{
            applications = @{
                includeApplications = @("All")
            }
            users = @{
                includeUsers  = @("all")
                excludeRoles  = $AdminRolesIds
            }
            locations = @{
                includeLocations = $AllBadRepIDs
            }
        }
        grantControls = @{
            operator        = "OR"
            builtInControls = @("block")
        }
    }

    $existingPolicy = Get-MgIdentityConditionalAccessPolicy |
        Where-Object { $_.DisplayName -eq "BadRep IP Block" }

    if ($null -ne $existingPolicy) {
        Write-Host "Conditional Access Policy 'BadRep IP Block' already exists - skipping." -BackgroundColor DarkBlue -ForegroundColor White
    }
    else {
        try {
            New-MgIdentityConditionalAccessPolicy -BodyParameter $repblockparams
            Write-Host "Conditional Access Policy 'BadRep IP Block' created successfully." -BackgroundColor DarkGreen -ForegroundColor White
        }
        catch {
            Write-Host "Failed to create 'BadRep IP Block' policy: $($_.Exception.Message)" -BackgroundColor DarkRed -ForegroundColor White
        }
    }
}

##############################!###################################################################################################
##############################!###################################################################################################
###########################!#########Create Sign-in Risk Block CAP################################################################
############################!#####################################################################################################
##############################!###################################################################################################
Write-Host "Creating Sign-In Risk Block Policy" -BackgroundColor DarkBlue -ForegroundColor White
Start-Sleep -Seconds 1

# Get Global Administrator role ID
$AdminRolesIds = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object -FilterScript {$_.DisplayName -like '*Global Administrator'} | Select-Object -ExpandProperty Id

# Create the Conditional Access Policy
$conditions = @{
    Users = @{
        IncludeUsers = @("all")
        ExcludeRoles = $AdminRolesIds
    }
    Applications = @{
        IncludeApplications = @("all")
    }
    SignInRiskLevels = @("medium", "high")
}

$controls = @{
    Operator = "OR"
    BuiltInControls = @("block")
}

$policyName = "Sign-In Risk Block"

$policyExists = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.displayName -eq $policyName }

if ($null -ne $policyExists) {
    Write-Host "Conditional Access Policy 'Sign-In Risk Block' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
} 
else {
    New-MgIdentityConditionalAccessPolicy -DisplayName $policyName -State "Enabled" -Conditions $conditions -GrantControls $controls
    Write-Host "Conditional Access Policy 'Sign-In Risk Block' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
}

#############################!#########################################################
########################!##############################################################
###!###########Show Results#!###########################################################
############################!##########################################################
##############################!########################################################
$caps = Get-MgIdentityConditionalAccessPolicy | Select DisplayName, CreatedDateTime, State
Write-Host "The Following Conditional Access Policies Were Created or Already Exist:" -BackgroundColor DarkBlue -ForegroundColor White
$caps
Start-Sleep -Seconds 2
Write-Host "Now disconnecting from AzureAD/Graph" -BackgroundColor DarkBlue -ForegroundColor White

#################################!#####################################################
################################!######################################################
##########!######Disconnect###########################################################
##################################!####################################################
###################################!###################################################
Disconnect-MgGraph
