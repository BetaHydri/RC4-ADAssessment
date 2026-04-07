function Get-GuidancePlainText
{
  <#
    .SYNOPSIS
        Generates a plain-text remediation guidance document for the RC4/DES assessment.

    .DESCRIPTION
        Builds and returns a formatted plain-text string containing the complete set of
        manual validation steps, remediation guidance, and reference documentation links for
        addressing DES and RC4 Kerberos encryption issues in Active Directory. The output
        includes domain name, generation date, and tool version in the header, and covers all
        11 standard guidance sections without Unicode decorators so the text is safe for
        plain-text file export.

    .PARAMETER Domain
        The Active Directory domain name to include in the guidance document header.

    .PARAMETER AssessmentDate
        The date/time string to include in the guidance document header.

    .PARAMETER Version
        The module version string to include in the guidance document header.

    .EXAMPLE
        $text = Get-GuidancePlainText -Domain "contoso.com" -AssessmentDate (Get-Date -Format "yyyy-MM-dd") -Version "1.0.0"
        $text | Out-File -FilePath "C:\Reports\guidance.txt"
    #>
  param(
    [string]$Domain,
    [string]$AssessmentDate,
    [string]$Version
  )

  $sb = [System.Text.StringBuilder]::new()
  [void]$sb.AppendLine("================================================================================")
  [void]$sb.AppendLine("DES/RC4 Kerberos Encryption Assessment - Guidance Reference")
  [void]$sb.AppendLine("================================================================================")
  [void]$sb.AppendLine("Domain:          $Domain")
  [void]$sb.AppendLine("Generated:       $AssessmentDate")
  [void]$sb.AppendLine("Tool Version:    v$Version")
  [void]$sb.AppendLine("================================================================================")
  [void]$sb.AppendLine("")
  [void]$sb.AppendLine("RECOMMENDED MANUAL VALIDATION STEPS")
  [void]$sb.AppendLine("")
  [void]$sb.AppendLine(@"
1. Event Log Monitoring Setup
   ------------------------------------------------------------
   Enable advanced Kerberos auditing on Domain Controllers:
ktpass command reference:
       https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ktpass
     - Kerberos SSO with Apache on Linux (keytab creation):
       https://docs.active-directory-wp.com/Networking/Single_Sign_On/Kerberos_SSO_with_Apache_on_Linux.html
     - Configure AD authentication with SQL Server on Linux (keytab tutorial):
       https://learn.microsoft.com/en-us/sql/linux/sql-server-linux-ad-auth-adutil-tutorial
   [x] Audit Kerberos Service Ticket Operations: Success and Failure

   Event IDs to monitor:
   * 4768: TGT Request (TicketEncryptionType field)
   * 4769: Service Ticket Request (TicketEncryptionType field)

   Encryption Type Values:
   * 0x1 or 0x3: DES (CRITICAL - should be 0)
   * 0x17: RC4-HMAC (WARNING - should be 0)
   * 0x11 or 0x12: AES (GOOD - expected value)

2. Splunk/SIEM Query Examples
   ------------------------------------------------------------

   Splunk query to detect RC4 usage:
   index=windows EventCode=4768 OR EventCode=4769
   | eval EncType=if(TicketEncryptionType="0x17", "RC4",
                     if(TicketEncryptionType="0x3", "DES",
                     if(TicketEncryptionType="0x1", "DES",
                     if(TicketEncryptionType="0x11", "AES128",
                     if(TicketEncryptionType="0x12", "AES256", "Unknown")))))
   | where EncType="RC4" OR EncType="DES"
   | stats count by TargetUserName, EncType
   | sort -count

   This shows which accounts are still using RC4/DES encryption.

3. GPO Validation
   ------------------------------------------------------------

   Verify GPO is applied and effective:

   On a Domain Controller:
   PS> gpresult /h C:\gpresult.html
   PS> Start-Process C:\gpresult.html

   Look for: "Network security: Configure encryption types allowed for Kerberos"
   Should show: AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types
   Should NOT show: DES_CBC_CRC, DES_CBC_MD5, RC4_HMAC_MD5

4. Computer Object Assessment (If Needed)
   ------------------------------------------------------------

   Post-November 2022 Update Clarification:

   RC4 fallback ONLY occurs when BOTH conditions are true:
   a) msDS-SupportedEncryptionTypes on CLIENT is set to non-zero value
   b) msDS-SupportedEncryptionTypes on DC does NOT include AES

   If your DCs have AES configured via GPO, client computers will inherit AES
   even if their msDS-SupportedEncryptionTypes attribute is not populated.

   You do NOT need to populate this attribute on all 100,000+ computers if:
   [x] DCs have AES configured (via GPO or attribute)
   [x] Event logs show no RC4 usage (0x17)

   To verify a specific computer:
   PS> Get-ADComputer "COMPUTERNAME" -Properties msDS-SupportedEncryptionTypes

   Value of 0 or empty: Inherits from DC (normal and secure post-Nov 2022)
   Value with 0x4 bit: Has RC4 explicitly set (investigate why)

5. Trust Validation
   ------------------------------------------------------------

   Post-November 2022: Trusts default to AES when attribute is not set.

   To verify trust encryption from both sides:
   PS> Get-ADTrust -Filter * | Select-Object Name, msDS-SupportedEncryptionTypes

   If msDS-SupportedEncryptionTypes is 0 or empty: Uses AES (secure)
   If set to 0x18: Explicitly configured for AES-only (secure, recommended)
   If set to 0x1C: Explicit RC4 exception with AES (review - remove RC4 when possible)
   If includes 0x4 without AES: RC4-only (critical - investigate)

6. KRBTGT Account & Service Account Hygiene
   ------------------------------------------------------------

   KRBTGT Password Rotation:
   * The KRBTGT password encrypts all TGTs in the domain
   * If never rotated since pre-AES era, only RC4/DES keys may exist
   * Microsoft recommends rotation at least every 180 days
   * AD retains the CURRENT and PREVIOUS KRBTGT password (N and N-1)
   * Rotate TWICE to flush out old keys entirely

   WARNING: KRBTGT Rotation Step-by-Step Procedure:

   a) Pre-Rotation Checks:
      * Confirm ALL Domain Controllers are online and replicating
        PS> repadmin /replsummary
        PS> Get-ADDomainController -Filter * | ForEach-Object {
              Test-Connection ``$_.HostName -Count 1 -Quiet }
      * Note the current password age:
        PS> Get-ADUser krbtgt -Properties PasswordLastSet |
            Select-Object Name, PasswordLastSet

   b) First Rotation:
      PS> Reset-ADAccountPassword -Identity krbtgt -NewPassword ``
            (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force) -Reset
      * Alternative using AD Users & Computers:
        Right-click krbtgt > Reset Password > enter random complex password
      * After reset, AD still accepts tickets encrypted with the
        PREVIOUS password (N-1), so existing TGTs remain valid.

   c) Wait for Replication:
      * Wait at LEAST 10-12 hours (or 2x the maximum TGT lifetime,
        which defaults to 10 hours) so all outstanding TGTs expire.
      * Verify the password change has replicated to ALL DCs:
        PS> Get-ADDomainController -Filter * | ForEach-Object {
              Get-ADUser krbtgt -Server ``$_.HostName -Properties PasswordLastSet |
              Select-Object @{N='DC';E={``$_.DistinguishedName.Split(',')[1]}},
                            PasswordLastSet }
      * Monitor for Kerberos errors (Event IDs 4768/4769 failures,
        Event ID 4771 with failure code 0x18 = bad password).
      * If you see widespread authentication failures, do NOT
        proceed with the second rotation; investigate first.

   d) Second Rotation:
      PS> Reset-ADAccountPassword -Identity krbtgt -NewPassword ``
            (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force) -Reset
      * After this, only the two newest passwords are valid.
        Any tickets from the original (pre-rotation) key are now invalid.
      * Wait for replication again and monitor for errors.

   e) Post-Rotation Validation:
      PS> Get-ADUser krbtgt -Properties PasswordLastSet, ``
            'msDS-SupportedEncryptionTypes' |
            Select-Object Name, PasswordLastSet, msDS-SupportedEncryptionTypes
      PS> Get-WinEvent -FilterHashtable @{LogName='Security';Id=4771;
            StartTime=(Get-Date).AddHours(-2)} -ErrorAction SilentlyContinue |
            Where-Object { ``$_.Message -match 'krbtgt' }

   Important Caveats:
   * NEVER rotate KRBTGT more than twice in quick succession
   * Golden Ticket attacks are invalidated by a double rotation
   * Azure AD Connect / Entra Connect: rotation is safe as it
     does not use Kerberos TGTs for cloud sync
   * Read-Only DCs (RODCs) have their own krbtgt_XXXXX accounts;
     these are rotated independently if needed
   * Consider using Microsoft's official KRBTGT reset script:
     https://github.com/microsoft/New-KrbtgtKeys.ps1

   Linux / Kerberos Keytab Impact:
   * KRBTGT or service account password rotation INVALIDATES
     any Kerberos keytab files generated from that account's previous password.
   * Linux services using AD-based Kerberos AES256 authentication
     (Apache, Nginx, SSSD, Samba, PostgreSQL, IBM WebSphere, etc.) will fail
     to authenticate until their keytab files are regenerated.
   * After password rotation, regenerate keytabs:
     # From Windows (for a service account, e.g. HTTP/linux.domain.com):
     PS> ktpass -princ HTTP/linux.domain.com@DOMAIN.COM ``
           -mapuser DOMAIN\svc_linux -pass <NewPassword> ``
           -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL ``
           -out c:\temp\linux.keytab
     # From Linux:
     $ ktutil
     ktutil: addent -password -p HTTP/linux.domain.com@DOMAIN.COM ``
              -k 1 -e aes256-cts-hmac-sha1-96
     ktutil: wkt /etc/krb5.keytab
   * Always test with: kinit -kt /etc/krb5.keytab <principal>
   * References:
     - AD Hardening Series Part 4 - Enforcing AES:
       https://techcommunity.microsoft.com/blog/yourwindowsserverpodcast/active-directory-hardening-series---part-4---enforcing-aes-for-kerberos/4260477
     - ktpass command reference:
       https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ktpass
     - Kerberos SSO with Apache on Linux (keytab creation):
       https://docs.active-directory-wp.com/Networking/Single_Sign_On/Kerberos_SSO_with_Apache_on_Linux.html
     - Configure AD authentication with SQL Server on Linux (keytab tutorial):
       https://learn.microsoft.com/en-us/sql/linux/sql-server-linux-ad-auth-adutil-tutorial

   Check KRBTGT:
   PS> Get-ADUser krbtgt -Properties PasswordLastSet, msDS-SupportedEncryptionTypes |
       Select-Object Name, PasswordLastSet, msDS-SupportedEncryptionTypes

   Service Accounts with RC4/DES:
   PS> Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ``
       msDS-SupportedEncryptionTypes, PasswordLastSet, ServicePrincipalName |
       Where-Object { ``$_.'msDS-SupportedEncryptionTypes' -band 4 -and
                       -not (``$_.'msDS-SupportedEncryptionTypes' -band 0x18) } |
       Select-Object Name, PasswordLastSet, msDS-SupportedEncryptionTypes

   Remove USE_DES_KEY_ONLY flag:
   PS> Get-ADUser -Filter 'UserAccountControl -band 2097152' |
       ForEach-Object { Set-ADAccountControl ``$_ -UseDESKeyOnly ``$false }

   Update service accounts to AES:
   PS> Set-ADUser "ServiceAccount" -Replace @{'msDS-SupportedEncryptionTypes'=24}
   # Then reset the password to generate new AES keys
   # After changing encryption types, purge cached tickets:
   # CMD> klist purge
   # For Linux services using keytabs, regenerate keytab files
   # after password reset (see Linux/Kerberos Keytab Impact above).

7. RC4 Disablement Timeline & Registry Keys (CVE-2026-20833)
   ------------------------------------------------------------

   CRITICAL TIMELINE:
   * January 2026: Security updates add RC4DefaultDisablementPhase
     registry key. Audit events (KDCSVC 201-209) logged in System log.
     Set to 2 on all DCs to enable Enforcement mode.
   * April 2026: Enforcement phase - DefaultDomainSupportedEncTypes
     defaults to AES-only (0x18). Manual rollback still possible.
   * July 2026: Full enforcement - RC4DefaultDisablementPhase
     registry key removed. RC4 blocked for all accounts without explicit
     RC4 in msDS-SupportedEncryptionTypes.

   Registry Keys to Configure:
   * HKLM\SYSTEM\CurrentControlSet\Services\Kdc

   a) RC4DefaultDisablementPhase (DWORD):
      * Value = 0: RC4 disablement not active
      * Value = 1: Audit mode only (logs KDCSVC events but allows RC4)
      * Value = 2: Enforcement mode (blocks RC4 for default accounts)
      * Deploy to ALL Domain Controllers after January 2026 updates
      PS> Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' ``
            -Name 'RC4DefaultDisablementPhase' -Value 2 -Type DWord

   b) DefaultDomainSupportedEncTypes (DWORD):
      * Controls default encryption types for the domain
      * After April 2026 updates, defaults to 0x18 (AES-only)
      * Should be set to 0x18 (24) for AES-only (recommended)
      * Do NOT set to 0x1C domain-wide unless absolutely necessary
        - this leaves ALL accounts vulnerable to CVE-2026-20833
        - use per-account msDS-SupportedEncryptionTypes = 0x1C instead
      PS> # Check current value:
      PS> Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' ``
            -Name 'DefaultDomainSupportedEncTypes' -ErrorAction SilentlyContinue

   * GPO Preference path for DefaultDomainSupportedEncTypes:
     Computer Configuration > Preferences > Windows Settings > Registry
     > DefaultDomainSupportedEncTypes

   * KDCSVC System Event Log Monitoring:
     Monitor events 201-209 (Provider: KDCSVC) in the System log.
     These identify accounts and configurations at risk before enabling
     Enforcement mode.

   Reference: https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc

8. Explicit RC4 Exception Workflow (CVE-2026-20833)
   ------------------------------------------------------------

   After April 2026 (Enforcement phase), RC4 is blocked for accounts with
   default encryption configuration. After July 2026, the RC4DefaultDisablementPhase
   registry key is removed entirely. Use this workflow for exceptions:

   a) Step 1: Try AES First
      PS> Set-ADUser "svc_LegacyApp" -Replace @{'msDS-SupportedEncryptionTypes'=24}
      PS> Set-ADAccountPassword "svc_LegacyApp" -Reset
      CMD> klist purge
      * Test application access

   b) Step 2: If AES Fails, Add Explicit RC4 Exception
      Per CVE-2026-20833 guidance, use 0x1C (RC4 + AES128 + AES256):

      For USER/SERVICE accounts:
      PS> Set-ADUser "svc_LegacyApp" -Replace @{'msDS-SupportedEncryptionTypes'=0x1C}
      PS> Set-ADAccountPassword "svc_LegacyApp" -Reset
      CMD> klist purge
      * Test application access

      For COMPUTER accounts (rare but possible):
      PS> Set-ADComputer "LEGACYHOST" -Replace @{'msDS-SupportedEncryptionTypes'=0x1C}
      CMD> klist purge
      * Test application access

   c) Last Resort: Domain-Wide RC4 Fallback (INSECURE)
      If per-account exceptions are not feasible:
      PS> Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' ``
            -Name 'DefaultDomainSupportedEncTypes' -Value 0x1C -Type DWord
      WARNING: This leaves ALL accounts vulnerable to CVE-2026-20833!
      * Only use as temporary measure while migrating to AES

   d) Step 3: Document and Plan
      * Document all accounts with explicit RC4 exceptions
      * Engage vendors for AES support on third-party systems
      * Plan upgrades or replacements for legacy systems
      * Set review dates to revisit each exception

   Reference: https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc

9. Accounts Missing AES Keys
   ------------------------------------------------------------

   Two detection paths identify accounts without AES Kerberos keys:

   Path A - Explicit Non-AES Encryption:
   Accounts where msDS-SupportedEncryptionTypes is explicitly set to a
   non-zero value WITHOUT AES bits (0x18). These accounts are configured
   for RC4-only or DES-only encryption regardless of password age.
   Examples: 0x4 (RC4-only), 0x3 (DES-only), 0x7 (DES+RC4, no AES).

   Path B - Attribute Not Set + Old Password:
   Accounts where msDS-SupportedEncryptionTypes is not set (null/0) AND
   the password is older than 5 years. These accounts may predate the
   DFL 2008 upgrade and never had AES keys generated.

   Find Path A accounts (explicit non-AES):
   PS> Get-ADUser -LDAPFilter '(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(msDS-SupportedEncryptionTypes=*))' ``
       -Properties 'msDS-SupportedEncryptionTypes', PasswordLastSet, lastLogonTimestamp |
       Where-Object { ``$enc = ``$_.'msDS-SupportedEncryptionTypes';
                       ``$enc -and ``$enc -ne 0 -and -not (``$enc -band 0x18) } |
       Select-Object Name, PasswordLastSet,
           @{N='EncType';E={``$_.'msDS-SupportedEncryptionTypes'}},
           @{N='LastLogon';E={
               if (``$_.lastLogonTimestamp) { [DateTime]::FromFileTime(``$_.lastLogonTimestamp) }
               else { 'Never' }
           }}

   Find Path B accounts (attribute not set + old password, including last logon):
   PS> Get-ADUser -Filter 'Enabled -eq ``$true' -Properties PasswordLastSet, ``
       'msDS-SupportedEncryptionTypes', lastLogonTimestamp |
       Where-Object { ``$_.PasswordLastSet -lt (Get-Date).AddYears(-5) -and
                       (-not ``$_.'msDS-SupportedEncryptionTypes' -or
                        ``$_.'msDS-SupportedEncryptionTypes' -eq 0) } |
       Select-Object Name, PasswordLastSet, @{N='LastLogon';E={
           if (``$_.lastLogonTimestamp) { [DateTime]::FromFileTime(``$_.lastLogonTimestamp) }
           else { 'Never' }
       }}

   * Accounts with recent lastLogonTimestamp: actively in use, prioritize
   * Accounts that never logged on or >90 days: consider disabling first

   Remediation for Path A (explicit non-AES):
   First set the account to AES-only, then reset the password:
   PS> Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}
   PS> Set-ADAccountPassword '<AccountName>' -Reset; klist purge

   Remediation for Path B (attribute not set + old password):

   a) Option 1: Reset Password (Simple)
      * Reset password to generate AES keys
      * Update services running under these accounts with new password
      * After reset, AES keys are automatically generated

   b) Option 2: Fine-Grained Password Policy (Zero-Disruption)
      Use a temporary FGPP to bypass domain password history requirements,
      allowing you to reset the password with the SAME value.

      Step 1: Create a temporary FGPP (one-time setup):
      PS> New-ADFineGrainedPasswordPolicy -Name 'Temp_AES_Key_Fix' ``
            -Precedence 1 ``
            -PasswordHistoryCount 0 ``
            -MinPasswordAge  '0.00:00:00' ``
            -MaxPasswordAge  '0.00:00:00' ``
            -ComplexityEnabled ``$false ``
            -MinPasswordLength 0 ``
            -LockoutThreshold 0 ``
            -ReversibleEncryptionEnabled ``$false

      Step 2: Apply FGPP to the target account:
      PS> Add-ADFineGrainedPasswordPolicySubject -Identity 'Temp_AES_Key_Fix' ``
            -Subjects '<AccountName>'

      Step 3: Reset password with the same value:
      PS> Set-ADAccountPassword '<AccountName>' -Reset ``
            -NewPassword (ConvertTo-SecureString '<SamePassword>' -AsPlainText -Force)

      Step 4: Force replication to all DCs:
      CMD> repadmin /syncall /AdePq

      Step 5: Remove FGPP from the account:
      PS> Remove-ADFineGrainedPasswordPolicySubject -Identity 'Temp_AES_Key_Fix' ``
            -Subjects '<AccountName>'

      Step 6: Verify AES keys exist (Event ID 4768 should now show AES):
      PS> Get-ADUser '<AccountName>' -Properties msDS-SupportedEncryptionTypes

   c) Option 3: Explicitly Set AES Encryption Types
      In some cases, resetting the password alone is not enough. If Event ID
      4768 still shows 'Available Keys: RC4' after the password reset, you
      must explicitly set the account's msDS-SupportedEncryptionTypes to AES:

      PS> Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}
      PS> Set-ADAccountPassword '<AccountName>' -Reset ``
            -NewPassword (ConvertTo-SecureString '<Password>' -AsPlainText -Force)
      CMD> klist purge

      After this, Event ID 4768 should show:
        MSDS-SupportedEncryptionTypes: 0x18 (AES128-SHA96, AES256-SHA96)
        Available Keys: AES-SHA1, RC4

      NOTE: The 'Available Keys' field always lists RC4 as available (AD
      stores RC4 keys for all accounts). What matters is that AES is
      listed FIRST and that 0x18 is set on the account.

   WARNING: For service accounts, coordinate password reset with
   application teams to avoid service disruptions.
   WARNING: For Linux services using keytabs, regenerate keytab files
   after password reset (see Linux/Kerberos Keytab Impact above).

10. Microsoft Kerberos-Crypto Tools
   ------------------------------------------------------------

   Microsoft provides complementary scripts for RC4 detection:
   * Get-KerbEncryptionUsage.ps1 - Detects RC4 usage from events 4768/4769
   * List-AccountKeys.ps1 - Lists account encryption key types

   Download from: https://github.com/microsoft/Kerberos-Crypto

   More info: https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-rc4

11. Recommended Monitoring Schedule
   ------------------------------------------------------------

   * Weekly: Check for RC4/DES events (automated alert)
   * Monthly: Review this assessment
   * Quarterly: Full security audit including Kerberos encryption
   * Before major changes: Re-run assessment


Reference Documentation:
   * KB5021131: Managing Kerberos protocol changes post-November 2022
   * CVE-2026-20833: RC4 KDC service ticket issuance (KB5073381)
   * https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc
   * https://techcommunity.microsoft.com/blog/askds/what-happened-to-kerberos-authentication-after-installing-the-november-2022oob-u/3696351
   * https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797
   * https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-rc4
   * https://github.com/microsoft/Kerberos-Crypto
"@)
  return $sb.ToString()
}
