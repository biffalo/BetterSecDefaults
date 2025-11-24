# BetterSecDefaults 🛡️

An automated PowerShell script for Entra ID that creates enterprise-grade Conditional Access policies to provide significantly improved security over Microsoft's basic "Security Defaults". 

**Who is this for?** Organizations that are currently using Security Defaults or have only basic Conditional Access policies in place and want to quickly level up their security posture.

**Important Note:** While these policies provide strong baseline security, they are not bulletproof. Conditional Access policies should always be tailored to your organization's specific needs, risk tolerance, and operational requirements.

## Related Resources

For additional Microsoft 365 security improvements, check out [Easy Wins Email Defense](https://github.com/biffalo/easy-wins-email-defense).

## Scripts in This Repository

- **[AZ-BetterSecDefaults.ps1](https://github.com/biffalo/BetterSecDefaults/blob/main/AZ-BetterSecDefaults.ps1)** - Main script that creates all policies
- **[AZ-BetterSecDefaults-Checker.ps1](https://github.com/biffalo/BetterSecDefaults/blob/main/AZ-BetterSecDefaults-Checker.ps1)** - Optional validation script to check for risky sign-ins

---

# Requirements 📃

Before running this script, ensure you have:

- ✅ **Entra ID Premium P2 License** (script will check and exit if not found)
- ✅ **Security Defaults DISABLED** (script will automatically disable if enabled)
- ✅ **[Microsoft Graph PowerShell Module](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0)** installed
- ✅ **Global Administrator credentials** for your tenant
- ✅ **Your WAN IP address in CIDR format** (e.g., 203.0.113.0/24)

---

# Policies Created 🔏

This script automatically creates 7 Conditional Access policies. All policies and named locations are checked for existence before creation to prevent duplicates.

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

**Technical Details:** This policy automatically downloads current threat intelligence feeds from:
- [X4BNet VPN IP List](https://github.com/X4BNet/lists_vpn) - 10,000+ known VPN provider IPs
- [SecOps-Institute Tor Exit Nodes](https://github.com/SecOps-Institute/Tor-IP-Addresses) - Current Tor exit node IPs

The script intelligently chunks these IPs into multiple named locations (800 IPs per location) to work within Azure's limits.

---

## 🔵 Policy 7 - Sign-In Risk Block
Creates sign-in risk policy that blocks medium and high-risk sign-in attempts identified by Azure AD Identity Protection. Excludes global admin role. 

**Best Practice:** This implements the best practice of risk-based conditional access, leveraging Microsoft's threat intelligence to automatically block suspicious authentication attempts in real-time.

---

# Usage 📘

### Running the Main Script

1. Download [AZ-BetterSecDefaults.ps1](https://github.com/biffalo/BetterSecDefaults/blob/main/AZ-BetterSecDefaults.ps1)
2. Open PowerShell as Administrator
3. Run the script: `.\AZ-BetterSecDefaults.ps1`

### What to Expect

The script will prompt you for:

1. **Azure Tenant ID** - Your organization's Entra ID tenant identifier
2. **Authentication** - You'll authenticate with Global Administrator credentials
3. **Trusted Location IP** - Your corporate WAN IP address in CIDR format (e.g., `203.0.113.0/24`)

The script will then:
- ✅ Verify your Entra ID P2 license
- ✅ Disable Security Defaults if enabled
- ✅ Create the "Trusted" named location with your IP
- ✅ Download threat intelligence IP lists
- ✅ Create all 7 Conditional Access policies
- ✅ Display a summary of created/existing policies

### Screenshots

![Script Banner](https://github.com/user-attachments/assets/8f8664f2-6149-4943-a4f3-378aa29e9565)

![Policy Creation](https://github.com/user-attachments/assets/fb59c4cc-086a-4703-b646-d139f09ca89f)

---

# Optional Checker Script 🔍

### What Does It Do?

The [AZ-BetterSecDefaults-Checker.ps1](https://github.com/biffalo/BetterSecDefaults/blob/main/AZ-BetterSecDefaults-Checker.ps1) script validates your environment by checking for risky sign-in activity that your new policies will prevent.

It searches the last 14 days of sign-in logs for:
- ✅ Successful logins from outside the USA
- ✅ Successful logins from MacOS devices
- ✅ Successful logins from Linux devices
- ✅ Successful logins using legacy authentication

### Why Use It?

Run this **before** implementing the policies to:
- Identify legitimate use cases you may need to accommodate
- Validate which policies are most relevant for your environment
- Gather data to justify the policy implementation to stakeholders
- Ensure you won't inadvertently block legitimate users

### Usage

```powershell
.\AZ-BetterSecDefaults-Checker.ps1
```

![Checker Script Output](https://github.com/user-attachments/assets/c6d3685c-d447-47b9-98e2-6b93b89ed699)

---

# Important Considerations ⚠️

### Before Implementation

1. **Test in Report-Only Mode** - Consider manually setting policies to "Report-Only" initially to monitor impact
2. **Review Exclusions** - Global Administrators are excluded from most policies - consider if this is appropriate for your org
3. **Geographic Restrictions** - The USA-only policy may not be suitable for global organizations
4. **Platform Restrictions** - Ensure MacOS/Linux blocks align with your environment
5. **Legacy Auth** - Verify no critical applications rely on legacy authentication before blocking

### After Implementation

1. **Monitor Sign-In Logs** - Watch for blocked users who may need exceptions
2. **Create Break-Glass Accounts** - Ensure emergency access accounts exist and are properly excluded
3. **Document Exceptions** - Maintain a record of any policy exceptions created
4. **Regular Reviews** - Periodically review policies to ensure they remain aligned with your needs

---

# Troubleshooting 🔧

### Common Issues

**"NamedLocation with id does not exist"**
- Ensure you're running the latest version of the script
- Named locations may take a few moments to propagate in Azure AD

**Policies already exist**
- The script safely skips existing policies - this is expected behavior if re-running

**VPN/TOR IP list download fails**
- Check your internet connectivity
- Verify you can access GitHub from your network
- The script requires outbound HTTPS access

---

# Contributing 🤝

Contributions are welcome! Please feel free to submit issues or pull requests.

### Credits

- **VPN IP List:** [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn)
- **Tor Exit Nodes:** [SecOps-Institute/Tor-IP-Addresses](https://github.com/SecOps-Institute/Tor-IP-Addresses)

---

# License 📄

This project is provided as-is for educational and security improvement purposes. Use at your own risk and always test in a non-production environment first.

---

# Author 👨‍💻

Created by [@biffalo](https://github.com/biffalo)

**Questions or suggestions?** Open an issue or reach out via GitHub!
