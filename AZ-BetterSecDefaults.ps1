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
# Prompt for tenant ID
$TenantId = Read-Host "Enter Azure TenantID"
# Authenticate to Azure AD and Microsoft Graph
Connect-MgGraph -TenantId $TenantId -Scopes "User.Read.All, Policy.ReadWrite.ConditionalAccess, Directory.Read.All, Policy.Read.All, RoleManagement.Read.All"
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
    $namedLocation = @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        displayName = "Trusted"
        isTrusted = $true
        ipRanges = @(@{ "cidrAddress" = $ipRanges })
    }

    # Create the named location policy
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -Body ($namedLocation | ConvertTo-Json -Depth 10)
    Write-Host "Named location 'Trusted' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1

    # Re-fetch the named location to get the ID
    $existingNamedLocation = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq $locationName }
}

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
            includeLocations = @("all")
            excludeLocations = @($existingNamedLocation.id)
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa", "domainJoinedDevice")
    }
}

# Check if the Conditional Access Policy "MFA for All" already exists
$existingPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
$policyExists = $existingPolicies.value | Where-Object { $_.displayName -eq "MFA for All" }

if ($null -ne $policyExists) {
    Write-Host "Conditional Access Policy 'MFA for All' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
} 
else {
    # Convert the policy to JSON
    $policyJson = $conditionalAccessPolicy | ConvertTo-Json -Depth 10

    # Create the Conditional Access Policy using MS Graph API
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Body $policyJson -ContentType "application/json"
    Write-Host "Conditional Access Policy 'MFA for All' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
}

#!################################################################################################################################
#!################################################################################################################################
##!#####BLOCK OUTISDE USA CAP#####################################################################################################
###!##############################################################################################################################
####!#############################################################################################################################
Write-Host "!OPTIONAL POLICY! - BLOCK OUTSIDE USA" -BackgroundColor DarkBlue -ForegroundColor White
Write-Host "Only create this policy if you have checked for international logins!" -BackgroundColor DarkYellow -ForegroundColor Black
Start-Sleep -Seconds 1
# Define the named location name
$locationName = "Outside USA"
$policyName = "Block Outside USA"

# List of all country codes except the United States
$countryCodes = @(
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", 
    "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", 
    "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", 
    "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS",  
    "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", 
    "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", 
    "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", 
    "UM", "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
)



# Prompt the user to enable or disable the policy
Write-Host "1. Create Block Outside USA policy" -BackgroundColor DarkRed -ForegroundColor White
Write-Host "2. Do NOT Create Block Outside USA policy" -BackgroundColor DarkGreen -ForegroundColor White
$selection = Read-Host "Please select an option (1 or 2)"

if ($selection -eq "1") {
    # Get the conditional access policy
    # Get the named location
    $existingLocation = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq $locationName }

# If the named location does not exist, create it
    if (-not $existingLocation) {
        $params = @{
            "@odata.type" = "#microsoft.graph.countryNamedLocation"
            DisplayName = $locationName
            CountriesAndRegions = $countryCodes
            IncludeUnknownCountriesAndRegions = $false
    }

        New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
        Write-Host "Named location '$locationName' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
} 
else {
    Write-Host "Named location '$locationName' already exists." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
}
    $existingPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq $policyName }

    # If the policy does not exist, create it
    if (-not $existingPolicy) {
        $namedLocation = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq $locationName }
        $adminRolesIds = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { $_.DisplayName -like '*Global Administrator' } | select -ExpandProperty Id

        $policy = @{
            displayName = $policyName
            state = "enabled"
            conditions = @{
                users = @{
                    includeUsers = @("All")
                    excludeRoles = $adminRolesIds
                }
                locations = @{
                    includeLocations = @($namedLocation.Id)
                }
                clientAppTypes = @("All")
                applications = @{
                    includeApplications = @("All")
                }
            }
            grantControls = @{
                operator = "OR"
                builtInControls = @("block")
            }
        }

        New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
        Write-Host "Conditional Access policy '$policyName' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
        Start-Sleep -Seconds 1
    } else {
        Write-Host "Conditional Access policy '$policyName' already exists." -BackgroundColor DarkBlue -ForegroundColor White
        Start-Sleep -Seconds 1
    }
} 
else {
    Write-Host "Block Outside USA policy was NOT created" -BackgroundColor Yellow
    Start-Sleep -Seconds 1
}



#######!##########################################################################################################################
###########!######################################################################################################################
####!###BLOCK MACOS CAP###########################################################################################################
#####!############################################################################################################################
######!###########################################################################################################################
Write-Host "OPTIONAL POLICY! Block Linux Sign Ins" -BackgroundColor DarkBlue -ForegroundColor White
Write-Host "Only create this policy if you have checked for MacOS Logins" -BackgroundColor DarkYellow -ForegroundColor Black
Start-Sleep -Seconds 1
# Function to create a conditional access policy
$policyName = "Block MAC OS"
function Create-ConditionalAccessPolicy {
    param (
        [string]$policyName
    )

    $AdminRolesIds = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object { $_.DisplayName -like '*Global Administrator' } | Select-Object -ExpandProperty Id

    # Define the conditions for the policy
    $conditions = @{
        Users = @{
            IncludeUsers = @("All")
            ExcludeRoles = $AdminRolesIds
        }
        ClientAppTypes = @("All")
        Platforms = @{
            IncludePlatforms = @("macOS")
        }
        Applications = @{
            IncludeApplications = @("All")
        }
    }

    # Define the policy grant controls
    $grantControls = @{
        Operator = "OR"
        BuiltInControls = @("block")
    }

    # Create the Conditional Access policy
    $policy = @{
        DisplayName = $policyName
        State = "enabled"
        Conditions = $conditions
        GrantControls = $grantControls
    }

    New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
    Write-Host "Conditional access policy '$policyName' has been created and enabled."
}

# Function to present options to the user
function Present-Options {
    param (
        [string]$message
    )
    Write-Host $message
    Write-Host "1. Create a conditional access policy to block Mac/OSX sign-ins" -BackgroundColor DarkRed -ForegroundColor White
    Write-Host "2. Do NOT create a block mac/osx policy" -BackgroundColor DarkGreen -ForegroundColor White
    Write-Host "3. Exit" -BackgroundColor DarkGreen -ForegroundColor White
    $selection = Read-Host "Please select an option (1, 2, or 3)"
    return $selection
}

# Present user with options
$existingPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq "Block MAC OS" }
$selection = Present-Options -message "Choose an option:"

if ($selection -eq "1") {
    if ($existingPolicy -ne $null) {
        Write-Host "The policy '$policyName' already exists." -BackgroundColor DarkBlue -ForegroundColor White
    } else {
        Create-ConditionalAccessPolicy -policyName $policyName
        Write-Host "Created '$policyName' Policy" -BackgroundColor DarkBlue -ForegroundColor White
    }
} elseif ($selection -eq "2") {
    Write-Host "Continuing without creating the policy..." -BackgroundColor DarkBlue -ForegroundColor White
} elseif ($selection -eq "3") {
    Write-Host "Exiting..."
} else {
    Write-Host "Invalid option. Please run the script again and select a valid option."
}



#!################################################################################################################################
#!################################################################################################################################
#!######BLOCK LINUX OS CAP########################################################################################################
#!################################################################################################################################
#!################################################################################################################################
Write-Host "OPTIONAL POLICY! Block Linux Sign Ins" -BackgroundColor DarkBlue -ForegroundColor White
Write-Host "Only create this policy if you have checked for Linux logins!" -BackgroundColor DarkYellow -ForegroundColor Black
Start-Sleep -Seconds 1
# Define policy options for Block Linux OS Policy
$AdminRolesIds = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object -FilterScript {$_.DisplayName -like '*Global Administrator'}| select -ExpandProperty Id
$params = @{
	displayName = "Block Linux OS"
	state = "enabled"
	conditions = @{


		applications = @{
			includeApplications = @(
				"All"
			)
		}
		users = @{
			includeUsers = @(
				"All"
			)

			excludeRoles = $AdminRolesIds

		}
		platforms = @{
			includePlatforms = @(
				"Linux"
			)
		}
		
	}
	grantControls = @{
		operator = "OR"
		builtInControls = @(
			"block"
		)
		
	}

}


# Function to present options to the user
function Present-Options {
    param (
        [string]$message
    )
    Write-Host $message
    Write-Host "1. Create a conditional access policy to block Linux sign-ins" -BackgroundColor DarkRed -ForegroundColor White
    Write-Host "2. Do NOT create a block Linux policy" -BackgroundColor DarkGreen -ForegroundColor White
    Write-Host "3. Exit" -BackgroundColor DarkGreen -ForegroundColor White
    $selection = Read-Host "Please select an option (1, 2, or 3)"
    return $selection
}

# Present user with options
$policyName = "Block Linux OS"
$existingPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq "Block Linux OS" }
$selection = Present-Options -message "Choose an option:"

if ($selection -eq "1") {
    if ($existingPolicy -ne $null) {
        Write-Host "The policy '$policyName' already exists." -BackgroundColor DarkBlue -ForegroundColor White
    } else {
        New-MgIdentityConditionalAccessPolicy -BodyParameter $params
        Write-Host "Created '$policyName' Policy" -BackgroundColor DarkBlue -ForegroundColor White
    }
} elseif ($selection -eq "2") {
    Write-Host "Continuing without creating the policy..." -BackgroundColor DarkBlue -ForegroundColor White
} elseif ($selection -eq "3") {
    Write-Host "Exiting..."
} else {
    Write-Host "Invalid option. Please run the script again and select a valid option."
}

##########!##################################################################
#########!###################################################################
########!#######Get Bad IPs and Split Due to AZ Limits#######################
############!################################################################
#############!###############################################################
Write-Host "POLICY - BLOCK BAD IPs" -BackgroundColor DarkBlue -ForegroundColor White
Write-Host "Getting Bad IP Lists" -BackgroundColor DarkBlue -ForegroundColor White
Start-Sleep -Seconds 2
# Define the URL of the file and the output paths
# Credit to X4BNet for the list
$fileUrl = "https://github.com/X4BNet/lists_vpn/raw/main/output/vpn/ipv4.txt"
$outputPath1 = "C:\temp\ipv4-part1.txt"
$outputPath2 = "C:\temp\ipv4-part2.txt"

# Create the output directory if it doesn't exist
$outputDir = "C:\temp"
if (-Not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir
}

# Download the file
$tempFile = "C:\temp\ipv4.txt"
Invoke-WebRequest -Uri $fileUrl -OutFile $tempFile

# Read the file content
$fileContent = Get-Content -Path $tempFile

# Split the file content
$part1 = $fileContent[0..1899]
$part2 = $fileContent[1900..($fileContent.Count - 1)]

# Save the parts to separate files
$part1 | Out-File -FilePath $outputPath1 -Encoding ASCII
$part2 | Out-File -FilePath $outputPath2 -Encoding ASCII

# Clean up the temporary file
Remove-Item -Path $tempFile
##############!###############################################################
##################!###########################################################
#################!######Get Tor exit node IPs#################################
################!#############################################################
###############!##############################################################
$url = "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst"
$outputPath = "C:\temp\ipv4-part3.txt"

# Download the file
Invoke-WebRequest -Uri $url -OutFile $outputPath

# Read the contents of the file
$fileContent = Get-Content -Path $outputPath

# Append /32 to each line
$fileContent = $fileContent | ForEach-Object { "$_/32" }

# Save the modified content back to the file
$fileContent | Set-Content -Path $outputPath
###################!#########################################################
####################!########################################################
#############!##Create BadRep1 Named Location################################
#####################!#######################################################
######################!######################################################
Write-Host "Creating Named Locations" -BackgroundColor DarkBlue -ForegroundColor White
# Define ranges1
# Read the contents of the text file into an array
$ipRanges1 = Get-Content -Path "C:\temp\ipv4-part1.txt"

# Check if the named location "BadRep1" already exists
$existingNamedLocation = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq "BadRep1" }

# Initialize the IpRanges array
$ip1RangesArray = @()

# Loop through each IP address in the text file and add it to the IpRanges array
foreach ($ip in $ipRanges1) {
    $ip1RangesArray += @{
        "@odata.type" = "#microsoft.graph.iPv4CidrRange"
        CidrAddress = $ip
    }
}

# Define the parameters for the named location
$bad1params = @{
    "@odata.type" = "#microsoft.graph.ipNamedLocation"
    DisplayName = "BadRep1"
    IsTrusted = $false
    IpRanges = $ip1RangesArray
}

if ($null -ne $existingNamedLocation) {
    $namedLocation = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq "BadRep1" } | select -ExpandProperty Id
    Write-Host "Named location 'BadRep1' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
} else {
    New-MgIdentityConditionalAccessNamedLocation -BodyParameter $bad1params
    Write-Host "Named location 'BadRep1' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
    $namedLocation = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq "BadRep1" } | select -ExpandProperty Id
}

################!#############################################################
###############!##############################################################
##############!#########Create BadRep2 Named Location#########################
#################!############################################################
##################!###########################################################
# Define ranges2
# Read the contents of the text file into an array
$ipRanges2 = Get-Content -Path "C:\temp\ipv4-part2.txt"

# Check if the named location "BadRep2" already exists
$existingNamedLocation = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq "BadRep2" }

# Initialize the IpRanges array
$ip2RangesArray = @()

# Loop through each IP address in the text file and add it to the IpRanges array
foreach ($ip in $ipRanges2) {
    $ip2RangesArray += @{
        "@odata.type" = "#microsoft.graph.iPv4CidrRange"
        CidrAddress = $ip
    }
}

# Define the parameters for the named location
$bad2params = @{
    "@odata.type" = "#microsoft.graph.ipNamedLocation"
    DisplayName = "BadRep2"
    IsTrusted = $false
    IpRanges = $ip2RangesArray
}

if ($null -ne $existingNamedLocation) {
    $namedLocation2 = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq "BadRep2" } | select -ExpandProperty Id
    Write-Host "Named location 'BadRep2' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
} else {
    New-MgIdentityConditionalAccessNamedLocation -BodyParameter $bad2params
    Write-Host "Named location 'BadRep2' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
    $namedLocation2 = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq "BadRep2" } | select -ExpandProperty Id
}

###################!##########################################################
####################!#########################################################
#####################!##Create BadRep3 Named Location#########################
######################!#######################################################
#######################!######################################################
# Define ranges3
# Read the contents of the text file into an array
$ipRanges3 = Get-Content -Path "C:\temp\ipv4-part3.txt"

# Check if the named location "BadRep3" already exists
$existingNamedLocation = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq "BadRep3" }

# Initialize the IpRanges array
$ip3RangesArray = @()

# Loop through each IP address in the text file and add it to the IpRanges array
foreach ($ip in $ipRanges3) {
    $ip3RangesArray += @{
        "@odata.type" = "#microsoft.graph.iPv4CidrRange"
        CidrAddress = $ip
    }
}

# Define the parameters for the named location
$bad3params = @{
    "@odata.type" = "#microsoft.graph.ipNamedLocation"
    DisplayName = "BadRep3"
    IsTrusted = $false
    IpRanges = $ip3RangesArray
}

if ($null -ne $existingNamedLocation) {
    $namedLocation3 = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq "BadRep3" } | select -ExpandProperty Id
    Write-Host "Named location 'BadRep3' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
} else {
    New-MgIdentityConditionalAccessNamedLocation -BodyParameter $bad3params
    Write-Host "Named location 'BadRep3' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
    $namedLocation3 = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq "BadRep3" } | select -ExpandProperty Id
}

del C:\temp\ipv4-part*
#########################!###################################################
#####################!#######################################################
######################!#Create Bad Rep Policy################################
#######################!#####################################################
########################!####################################################
Write-Host "Creating BadIP Rep Policy" -BackgroundColor DarkBlue -ForegroundColor White
$AdminRolesIds = Get-MgRoleManagementDirectoryRoleDefinition | Where-Object -FilterScript {$_.DisplayName -like '*Global Administrator'}| select -ExpandProperty Id
# Create the Conditional Access Policy
$repblockparams = @{
	displayName = "BadRep IP Block"
	state = "enabled"
	conditions = @{
		applications = @{
			includeApplications = @("All")
		}
		users = @{
			includeUsers = @("all")
			excludeRoles = @("$AdminRolesIds")
		}
		locations = @{
			includeLocations = @(
                                "$namedLocation"
                                "$namedLocation2"
                                "$namedLocation3"
                                )
		}
	}
	grantControls = @{
		operator = "OR"
		builtInControls = @("block")
	}
}
# Check if the Conditional Access Policy "BadRep1" exists. Skip creation if it does
$existingPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq "BadRep IP Block" }


if ($null -ne $existingPolicy ) {
    Write-Host "Conditional Access Policy 'BadRep IP Block' already exists. Skipping creation." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
} 
else {
    New-MgIdentityConditionalAccessPolicy -BodyParameter $repblockparams

    Write-Host "Conditional Access Policy 'BadRep IP Block' created successfully." -BackgroundColor DarkBlue -ForegroundColor White
    Start-Sleep -Seconds 1
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
