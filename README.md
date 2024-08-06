# BetterSecDefaults🛡️ #

A Powershell script for EntraID that creates a set of conditional access policies that will provide improved security over Microsoft's "Security Defaults".  This script is primarily for less mature orgs that are perhaps still using Microsofts "Security Defaults"  or only have very basic conditional access policies in place. These policies are certainly not bulletproof and good conditional access policies should be tailored to your org. 

# Requirements📃
🔵EntraID Premium P2 Lic (script will bail if not found)
🔵Security Defaults DISABLED (script will disable for you)
🔵Microsoft Graph Powershell Module [https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0]

# Policies🔏
** The following policies are created by this script

**Policy 1 - MFA For All**
Prompts you for trust location IP in CIDR format. Creates policy that requires MFA or hybrid join for any login coming from any network NOT in the "trusted" named location

**Policy 2 - OPTIONAL - Block Outside USA**
Optional policy. Blocks logins to all apps from outside of the United States. Excludes global admin role.

**Policy 3 - OPTIONAL - Block MAC OS**
Optional policy. Blocks all logins from MacOS devices. Excludes global admin role.

**Policy 4 - OPTIONAL - Block Linux OS**
Optional policy. Blocks all logins from Linux devices. Excludes global admin role.

**Policy 5 - BadRep IP Block**
Gets IP lists for known VPN providers and Tor exit nodes. Blocks login from IPs that match. Excludes global admin role.

**Policy 6 - Sign-In Risk Block**
Creates sign in risk block policy (medium and high) and blocks risky sign-ins that match. Excludes global admin role.



