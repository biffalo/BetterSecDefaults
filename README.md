# BetterSecDefaults🛡️ #

An interactive Powershell script for EntraID that creates a set of conditional access policies that will provide improved security over Microsoft's "Security Defaults".  This script is primarily for less mature orgs that are perhaps still using Microsofts "Security Defaults"  or only have very basic conditional access policies in place. These policies are certainly not bulletproof and good conditional access policies should be tailored to your org. 

For more security suggestions for Azure/365 check out [Easy Wins Email Defense](https://github.com/biffalo/easy-wins-email-defense).

All policies and named locations are checked for their existence prior to creation.

[AZ-BetterSecDefaults.ps1](https://github.com/biffalo/BetterSecDefaults/blob/main/AZ-BetterSecDefaults.ps1)

[AZ-BetterSecDefaults-Checker.ps1](https://github.com/biffalo/BetterSecDefaults/blob/main/AZ-BetterSecDefaults-Checker.ps1)

# Requirements📃

🔵EntraID Premium P2 Lic (script will exit if not found)

🔵Security Defaults DISABLED (script will disable if enabled)

🔵[Microsoft Graph Powershell Module](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0)

# Policies 🔏
**The following policies are created by this script**

## 🔵 Policy 1 - MFA For All
Prompts you for trusted location IP in CIDR format. Creates policy that requires MFA or hybrid join for any login coming from any network NOT in the "trusted" named location. 

**Best Practice:** This satisfies the best practice of enforcing multi-factor authentication for all users while providing a practical exception for corporate networks with compliant devices.

---

## 🔵 Policy 2 - Block Outside USA
Blocks logins to all apps from outside of the United States. Excludes global admin role. 

**Best Practice:** This helps organizations satisfy compliance requirements for data sovereignty and geographic access restrictions, reducing the attack surface by limiting access to expected geographic regions.

---

## 🔵 Policy 3 - Block MAC OS
Blocks all logins from MacOS devices. Excludes global admin role. 

**Best Practice:** This enforces platform standardization best practices and helps organizations maintain a Windows-only environment for security, compliance, and management consistency.

---

## 🔵 Policy 4 - Block Linux OS
Blocks all logins from Linux devices. Excludes global admin role. 

**Best Practice:** This supports endpoint security best practices by preventing authentication from potentially unmanaged or non-compliant Linux systems that may not meet organizational security standards.

---

## 🔵 Policy 5 - Block Legacy Auth
Blocks legacy authentication protocols (Exchange ActiveSync and other legacy clients) unless originating from a trusted location. 

**Best Practice:** This satisfies the critical best practice of eliminating legacy authentication methods that bypass modern security controls like MFA and are frequently exploited in attacks.

---

## 🔵 Policy 6 - BadRep IP Block
Downloads and processes IP lists for known VPN providers (10,000+ IPs) and Tor exit nodes, creating named locations and blocking authentication attempts from these sources. Excludes global admin role. 

**Best Practice:** This addresses the best practice of blocking anonymization services that are commonly used by threat actors to mask their true origin and evade geographic restrictions.

---

## 🔵 Policy 7 - Sign-In Risk Block
Creates sign-in risk policy that blocks medium and high-risk sign-in attempts identified by Azure AD Identity Protection. Excludes global admin role. 

**Best Practice:** This implements the best practice of risk-based conditional access, leveraging Microsoft's threat intelligence to automatically block suspicious authentication attempts in real-time.

# Usage📘
[AZ-BetterSecDefaults.ps1](https://github.com/biffalo/BetterSecDefaults/blob/main/AZ-BetterSecDefaults.ps1)

The script is designed to be interactive to guide you through policy creation where needed. Upon running the script you'll be prompted for the following information:

🟢Azure Tenant ID 

🟢Azure Creds (auth to Azure)

🟢WAN IP for trusted named location



![image](https://github.com/user-attachments/assets/8f8664f2-6149-4943-a4f3-378aa29e9565)

![image](https://github.com/user-attachments/assets/fb59c4cc-086a-4703-b646-d139f09ca89f)

# Optional Checker Script🔍

[AZ-BetterSecDefaults-Checker.ps1](https://github.com/biffalo/BetterSecDefaults/blob/main/AZ-BetterSecDefaults-Checker.ps1)

Optionally you can use the checker script which checks for successful interactive sign-ins from outside USA/MacOS/Linux/Legacy Auth and displays them when found. For speed only the last 14 days of logs are checked. 

![image](https://github.com/user-attachments/assets/c6d3685c-d447-47b9-98e2-6b93b89ed699)










