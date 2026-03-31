function Invoke-RC4Assessment {
<#
.SYNOPSIS
    Run a DES/RC4 Kerberos encryption assessment for a single Active Directory domain.
.DESCRIPTION
    Orchestrates all assessment functions for a single AD domain. By default, performs
    a fast config-only scan (DC encryption, trusts, KRBTGT, service accounts) using only
    AD attribute queries. When -AnalyzeEventLogs is specified, additionally connects to
    each DC for KDC registry settings, KDCSVC events (CVE-2026-20833), audit policy,
    and Security event log analysis (4768/4769). Produces a structured results hashtable
    and optional JSON/CSV/guidance exports.
.PARAMETER Domain
    Target domain to assess. Defaults to the current domain.
.PARAMETER Server
    Specific domain controller to query.
.PARAMETER AnalyzeEventLogs
    Analyze DC event logs for actual DES/RC4 ticket usage (Event IDs 4768/4769).
.PARAMETER EventLogHours
    Number of hours of event logs to analyze (1-168). Default: 24.
.PARAMETER ExportResults
    Export assessment results to JSON, CSV, and optionally guidance text files.
.PARAMETER IncludeGuidance
    Show full reference manual and export guidance text file when combined with -ExportResults.
.PARAMETER DeepScan
    Extends the assessment to scan all enabled user accounts (not just those with SPNs)
    and all enabled computer accounts (excluding DCs) for RC4/DES encryption configurations.
    Computers with the OS-default value 0x1C are reported as an INFO summary count;
    non-default RC4/DES computers are listed individually as WARNING.
.EXAMPLE
    Invoke-RC4Assessment

    Quick config-only scan: DCs, GPOs, trusts, KRBTGT, service accounts. No remote
    event log or registry queries. Fastest mode, safe for large environments.
.EXAMPLE
    Invoke-RC4Assessment -DeepScan

    Extended scan: also checks all enabled user accounts (not just SPN-bearing) and
    all computer accounts (excluding DCs). Still no remote DC queries — safe and fast.
.EXAMPLE
    Invoke-RC4Assessment -DeepScan -AnalyzeEventLogs -EventLogHours 168 -ExportResults

    Maximum coverage: deep account scan + KDC registry + KDCSVC events + 7 days of
    event logs. Connects remotely to every DC.
.EXAMPLE
    Invoke-RC4Assessment -Domain "contoso.com" -AnalyzeEventLogs -EventLogHours 48 -ExportResults
.EXAMPLE
    Invoke-RC4Assessment -Domain "contoso.com" -AnalyzeEventLogs -ExportResults -IncludeGuidance

    Full entry-point: assess a specific domain with event logs, export JSON/CSV/guidance, and display the reference manual.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$Domain,

    [Parameter()]
    [string]$Server,

    [Parameter()]
    [switch]$AnalyzeEventLogs,

    [Parameter()]
    [ValidateRange(1, 168)]
    [int]$EventLogHours = 24,

    [Parameter()]
    [switch]$ExportResults,

    [Parameter()]
    [switch]$IncludeGuidance,

    [Parameter()]
    [switch]$DeepScan
)

# Display header
Write-Header "DES/RC4 Kerberos Encryption Assessment v$script:Version" -Color "Cyan"

Write-Host @"

This tool performs a fast, accurate assessment of DES and RC4 encryption usage
in Active Directory based on post-November 2022 Microsoft updates.

Key improvements over v1.0:

"@ -ForegroundColor Gray

Write-Host "  $([char]0x2713) Fast execution (<5 minutes vs 5+ hours)" -ForegroundColor Gray
Write-Host "  $([char]0x2713) Post-Nov 2022 trust logic (AES default when not set)" -ForegroundColor Gray
Write-Host "  $([char]0x2713) Realistic computer object assessment (no unnecessary enumeration)" -ForegroundColor Gray
Write-Host "  $([char]0x2713) Event log analysis for actual usage vs theoretical risk" -ForegroundColor Gray
Write-Host "  $([char]0x2713) KRBTGT & service account encryption assessment" -ForegroundColor Gray
Write-Host "  $([char]0x2713) Actionable guidance for manual validation`n" -ForegroundColor Gray

# Set up parameters for AD commands
$serverParams = @{}
if ($PSBoundParameters.ContainsKey('Domain')) {
    if ($Domain) {
        # When domain is specified, try to resolve to a specific DC for clearer error messages
        try {
            $discoveredDC = Get-ADDomainController -DomainName $Domain -Discover -ErrorAction Stop
            # Extract hostname as a simple string (handle arrays, collections, and objects)
            if ($discoveredDC.HostName -is [array]) {
                $resolvedDC = [string]$discoveredDC.HostName[0]
            }
            elseif ($discoveredDC.HostName.Value) {
                # Handle ADPropertyValueCollection
                $resolvedDC = [string]$discoveredDC.HostName.Value
            }
            else {
                # Direct property access
                $resolvedDC = [string]$discoveredDC.HostName
            }
            $serverParams['Server'] = $resolvedDC
            Write-Finding -Status "INFO" -Message "Targeting domain: $Domain (using DC: $resolvedDC)"
        }
        catch {
            # If discovery fails, fall back to domain name
            $serverParams['Server'] = $Domain
            Write-Finding -Status "WARNING" -Message "Could not auto-discover DC for domain '$Domain', using domain name directly"
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Tip: Use -Server parameter to specify a specific DC if the domain is unreachable" -ForegroundColor Gray
        }
    }
}
elseif ($PSBoundParameters.ContainsKey('Server')) {
    if ($Server) {
        $serverParams['Server'] = $Server
        Write-Finding -Status "INFO" -Message "Targeting server: $Server"
    }
}

# Initialize results object
$results = @{
    AssessmentDate    = $script:AssessmentTimestamp
    Version           = $script:Version
    Domain            = if ($Domain) { $Domain } else { (Get-ADDomain).DNSRoot }
    DomainControllers = $null
    Trusts            = $null
    Accounts          = $null
    KdcRegistry       = $null
    KdcSvcEvents      = $null
    AuditPolicy       = $null
    EventLogs         = $null
    OverallStatus     = "Unknown"
    Recommendations   = @()
}

try {
    # 1. Domain Controller Assessment
    $results.DomainControllers = Get-DomainControllerEncryption -ServerParams $serverParams

    # 2. Trust Assessment
    $results.Trusts = Get-TrustEncryptionAssessment -ServerParams $serverParams

    # 3. KRBTGT & Account Assessment
    $results.Accounts = Get-AccountEncryptionAssessment -ServerParams $serverParams -DeepScan:$DeepScan

    # 4-5. Remote DC analysis (KDC registry, KDCSVC events, Security event logs)
    #       Gated behind -AnalyzeEventLogs because these require remote
    #       WinRM/RPC connections to every DC and can be slow in large environments.
    if ($AnalyzeEventLogs) {
        # 4. KDC Registry Assessment
        $results.KdcRegistry = Get-KdcRegistryAssessment -ServerParams $serverParams

        # 4b. KDCSVC System Event Assessment (CVE-2026-20833)
        $results.KdcSvcEvents = Get-KdcSvcEventAssessment -ServerParams $serverParams

        # 5a. Check audit policy first
        $results.AuditPolicy = Get-AuditPolicyCheck -ServerParams $serverParams

        # 5b. Analyze event logs
        $results.EventLogs = Get-EventLogEncryptionAnalysis -ServerParams $serverParams -Hours $EventLogHours
        # 5c. Correlate: accounts with AES configured in AD but using RC4 tickets (need password reset)
        if ($results.EventLogs.RC4Accounts.Count -gt 0 -and $results.Accounts) {
            # Correlate: accounts with AES configured in AD but using RC4 tickets (need password reset)
            # Service accounts with SPNs (RC4-only ones wouldn't have AES, skip them)
            # We want accounts that HAVE AES configured but are still issuing RC4 tickets
            try {
                $rc4EventAccounts = $results.EventLogs.RC4Accounts
                foreach ($acctName in $rc4EventAccounts) {
                    # Check if this account is NOT in the RC4-only lists (those are expected to use RC4)
                    $isKnownRC4 = $false
                    if ($results.Accounts.RC4OnlyServiceAccounts.Name -contains $acctName) { $isKnownRC4 = $true }
                    if ($results.Accounts.RC4OnlyMSAs.Name -contains $acctName) { $isKnownRC4 = $true }
                    if ($results.Accounts.DESFlagAccounts.Name -contains $acctName) { $isKnownRC4 = $true }

                    if (-not $isKnownRC4) {
                        # Look up the account in AD to check its msDS-SupportedEncryptionTypes
                        try {
                            # Try as user first, then computer
                            $adAccount = $null
                            try {
                                $adAccount = Get-ADUser -Identity $acctName -Properties 'msDS-SupportedEncryptionTypes', PasswordLastSet, Enabled @serverParams -ErrorAction Stop
                            }
                            catch {
                                try {
                                    $adAccount = Get-ADComputer -Identity $acctName -Properties 'msDS-SupportedEncryptionTypes', PasswordLastSet, Enabled @serverParams -ErrorAction Stop
                                }
                                catch {
                                    # Account not found by either type - skip
                                    continue
                                }
                            }

                            if ($adAccount) {
                                $encValue = $adAccount.'msDS-SupportedEncryptionTypes'
                                # Account has AES configured (bits 0x8 or 0x10) but is using RC4 tickets
                                # OR account has no encryption type set (inherits from GPO/domain default which is AES)
                                $hasAES = $encValue -and ($encValue -band 0x18)
                                $inheritsDefault = -not $encValue -or $encValue -eq 0

                                if ($hasAES -or $inheritsDefault) {
                                    $results.EventLogs.PasswordResetNeeded += @{
                                        Name            = $acctName
                                        EncryptionValue = if ($encValue) { $encValue } else { 0 }
                                        EncryptionTypes = if ($encValue) { Get-EncryptionTypeString -Value $encValue } else { "Not Set (inherits AES default)" }
                                        PasswordLastSet = $adAccount.PasswordLastSet
                                        PasswordAgeDays = if ($adAccount.PasswordLastSet) { [int]((Get-Date) - $adAccount.PasswordLastSet).TotalDays } else { -1 }
                                        Enabled         = $adAccount.Enabled
                                        Reason          = if ($inheritsDefault) { "Inherits AES default but using RC4 - password predates AES key generation" } else { "AES configured (0x$($encValue.ToString('X'))) but using RC4 - password reset needed to generate AES keys" }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Could not look up account '$acctName' for correlation: $($_.Exception.Message)"
                        }
                    }
                }

                if ($results.EventLogs.PasswordResetNeeded.Count -gt 0) {
                    Write-Finding -Status "WARNING" -Message "$($results.EventLogs.PasswordResetNeeded.Count) account(s) have AES configured but are still using RC4 tickets (password reset needed)"
                    foreach ($acct in $results.EventLogs.PasswordResetNeeded) {
                        $pwdAge = if ($acct.PasswordAgeDays -ge 0) { "pwd: $($acct.PasswordAgeDays)d" } else { "pwd: unknown" }
                        Write-Host "    $([char]0x2022) $($acct.Name) ($($acct.EncryptionTypes), $pwdAge)" -ForegroundColor Yellow
                    }
                    Write-Host "    $([char]0x2192) Reset passwords to generate AES keys: Set-ADAccountPassword '<Account>' -Reset" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Verbose "AES/RC4 correlation failed: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Section "Remote DC Analysis (KDC Registry, KDCSVC Events, Event Logs)"
        Write-Finding -Status "INFO" -Message "Remote DC analysis skipped. Use -AnalyzeEventLogs to enable."
        Write-Host "  This queries each DC for KDC registry settings, KDCSVC events (CVE-2026-20833)," -ForegroundColor Gray
        Write-Host "  audit policy, and Security event logs (4768/4769) for actual DES/RC4 ticket usage." -ForegroundColor Gray
        Write-Host "  Example: Invoke-RC4Assessment -AnalyzeEventLogs -EventLogHours 48" -ForegroundColor Gray
    }

    # 5. Overall Assessment
    Write-Section "Overall Security Assessment"

    $criticalIssues = 0
    $warnings = 0

    # Check for DES
    if ($results.DomainControllers.DESConfigured -gt 0) {
        $criticalIssues++
        $desDCs = ($results.DomainControllers.Details | Where-Object { $_.Status -match 'DES' }).Name -join ', '
        $results.Recommendations += @{
            Level   = "CRITICAL"
            Message = "[$($results.Domain)] Remove DES encryption from $($results.DomainControllers.DESConfigured) Domain Controller(s): $desDCs"
            Fix     = @(
                "Set-ADComputer <DCName> -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                "# 24 = AES128 + AES256 only. Apply to: $desDCs"
            )
        }
    }

    if ($results.Trusts.DESRisk -gt 0) {
        $criticalIssues++
        $desTrusts = ($results.Trusts.Details | Where-Object { $_.Status -match 'DES' }).Name -join ', '
        $results.Recommendations += @{
            Level   = "CRITICAL"
            Message = "[$($results.Domain)] Remove DES encryption from $($results.Trusts.DESRisk) trust(s): $desTrusts"
            Fix     = @(
                "Set-ADObject (Get-ADTrust '<TrustName>').DistinguishedName -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                "# Or clear the attribute to use AES default: -Clear 'msDS-SupportedEncryptionTypes'"
            )
        }
    }

    if ($results.EventLogs -and $results.EventLogs.DESTickets -gt 0) {
        $criticalIssues++
        $desAcctList = if ($results.EventLogs.DESAccounts.Count -gt 0) { ($results.EventLogs.DESAccounts | Select-Object -First 5) -join ', ' } else { 'unknown' }
        $results.Recommendations += @{
            Level   = "CRITICAL"
            Message = "[$($results.Domain)] DES tickets detected in event logs ($($results.EventLogs.DESTickets) tickets, accounts: $desAcctList)"
            Fix     = @(
                "# Investigate each account and update to AES:"
                "Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                "Set-ADAccountPassword '<AccountName>' -Reset; klist purge"
            )
        }
    }

    # Check for RC4
    if ($results.DomainControllers.RC4Configured -gt 0) {
        $warnings++
        $rc4DCs = ($results.DomainControllers.Details | Where-Object { $_.Status -match 'RC4' }).Name -join ', '
        $results.Recommendations += @{
            Level   = "WARNING"
            Message = "[$($results.Domain)] Remove RC4 encryption from $($results.DomainControllers.RC4Configured) Domain Controller(s): $rc4DCs"
            Fix     = @(
                "Set-ADComputer $rc4DCs -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                "# Or configure via GPO: 'Network security: Configure encryption types allowed for Kerberos' = AES128 + AES256 + Future encryption types"
            )
        }
    }

    if ($results.Trusts.RC4Risk -gt 0) {
        $warnings++
        $rc4Trusts = ($results.Trusts.Details | Where-Object { $_.Status -match 'RC4' }).Name -join ', '
        $results.Recommendations += @{
            Level   = "WARNING"
            Message = "[$($results.Domain)] $($results.Trusts.RC4Risk) trust(s) have RC4 enabled: $rc4Trusts"
            Fix     = @(
                "# Remove explicit setting to use AES default (post-Nov 2022):"
                "Set-ADObject (Get-ADTrust '<TrustName>').DistinguishedName -Clear 'msDS-SupportedEncryptionTypes'"
                "# Or set to AES-only: -Replace @{'msDS-SupportedEncryptionTypes'=24}"
            )
        }
    }

    if ($results.EventLogs -and $results.EventLogs.RC4Tickets -gt 0) {
        $criticalIssues++
        $rc4AcctList = if ($results.EventLogs.RC4Accounts.Count -gt 0) { ($results.EventLogs.RC4Accounts | Select-Object -First 5) -join ', ' } else { 'unknown' }
        $results.Recommendations += @{
            Level   = "CRITICAL"
            Message = "[$($results.Domain)] RC4 tickets detected in event logs ($($results.EventLogs.RC4Tickets) tickets, accounts: $rc4AcctList)"
            Fix     = @(
                "# For each account using RC4, try AES first:"
                "Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                "Set-ADAccountPassword '<AccountName>' -Reset; klist purge"
                "# If AES fails, add explicit RC4 exception (CVE-2026-20833 safe):"
                "# Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=0x1C}"
                "# 0x1C = RC4 (0x4) + AES128 (0x8) + AES256 (0x10) - allows RC4 tickets with AES support"
            )
        }
    }

    if ($results.EventLogs -and $results.EventLogs.PasswordResetNeeded.Count -gt 0) {
        $warnings++
        $prnList = ($results.EventLogs.PasswordResetNeeded | Select-Object -First 5).Name -join ', '
        $results.Recommendations += @{
            Level   = "WARNING"
            Message = "[$($results.Domain)] $($results.EventLogs.PasswordResetNeeded.Count) account(s) have AES configured but are using RC4 tickets - password reset needed: $prnList"
            Fix     = @(
                "# These accounts have AES in msDS-SupportedEncryptionTypes but lack AES keys"
                "# (password was never reset after AES was configured)"
                "Set-ADAccountPassword '<AccountName>' -Reset -NewPassword (ConvertTo-SecureString '<NewPassword>' -AsPlainText -Force)"
                "klist purge"
                "# For service accounts, use FGPP workaround to reset with same password (see -IncludeGuidance, Section 9b)"
            )
        }
    }

    # Check for KRBTGT and account issues
    if ($results.Accounts) {
        if ($results.Accounts.KRBTGT.Status -eq "CRITICAL") {
            $criticalIssues++
            $results.Recommendations += @{
                Level   = "CRITICAL"
                Message = "[$($results.Domain)] KRBTGT password is $($results.Accounts.KRBTGT.PasswordAgeDays) days old - rotate immediately"
                Fix     = @(
                    "# Step 1: Verify all DCs are replicating: repadmin /replsummary"
                    "# Step 2: First rotation:"
                    "Reset-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force) -Reset"
                    "# Step 3: Wait 10-12 hours, then second rotation (same command)"
                    "# IMPORTANT: Linux/Kerberos keytab impact - after KRBTGT rotation,"
                    "#   regenerate all keytab files (ktpass/ktutil) for Linux services"
                    "#   using AD-based Kerberos AES256 authentication."
                    "# See -IncludeGuidance for full KRBTGT rotation procedure"
                )
            }
        }
        elseif ($results.Accounts.KRBTGT.Status -eq "WARNING") {
            $warnings++
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] KRBTGT password is $($results.Accounts.KRBTGT.PasswordAgeDays) days old - consider rotation"
                Fix     = @(
                    "# Rotate KRBTGT password (double rotation with 10-12h wait between):"
                    "Reset-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force) -Reset"
                    "# IMPORTANT: Linux/Kerberos keytab impact - after KRBTGT rotation,"
                    "#   regenerate all keytab files (ktpass/ktutil) for Linux services"
                    "#   using AD-based Kerberos AES256 authentication."
                    "# See -IncludeGuidance for full procedure"
                )
            }
        }

        if ($results.Accounts.TotalDESFlag -gt 0) {
            $criticalIssues++
            $desNames = ($results.Accounts.DESFlagAccounts | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "CRITICAL"
                Message = "[$($results.Domain)] $($results.Accounts.TotalDESFlag) account(s) have USE_DES_KEY_ONLY flag: $desNames"
                Fix     = @(
                    "Get-ADUser -Filter 'UserAccountControl -band 2097152' | ForEach-Object { Set-ADAccountControl `$_ -UseDESKeyOnly `$false }"
                    "# Then reset password for each account to generate AES keys"
                )
            }
        }

        if ($results.Accounts.TotalRC4OnlySvc -gt 0) {
            $criticalIssues++
            $svcNames = ($results.Accounts.RC4OnlyServiceAccounts | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "CRITICAL"
                Message = "[$($results.Domain)] $($results.Accounts.TotalRC4OnlySvc) service account(s) have RC4/DES-only encryption: $svcNames"
                Fix     = @(
                    "# Update each service account to AES and reset password:"
                    "Set-ADUser '<ServiceAccount>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                    "Set-ADAccountPassword '<ServiceAccount>' -Reset; klist purge"
                    "# Update the service with the new password, then test access"
                )
            }
        }

        if ($results.Accounts.TotalRC4OnlyMSA -gt 0) {
            $warnings++
            $msaNames = ($results.Accounts.RC4OnlyMSAs | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] $($results.Accounts.TotalRC4OnlyMSA) Managed Service Account(s) have RC4-only encryption: $msaNames"
                Fix     = @(
                    "Set-ADServiceAccount '<MSAName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                )
            }
        }

        if ($results.Accounts.TotalRC4Exception -gt 0) {
            $warnings++
            $excNames = ($results.Accounts.RC4ExceptionAccounts | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] $($results.Accounts.TotalRC4Exception) account(s) have explicit RC4 exception (0x1C) - review and remove RC4 when possible: $excNames"
                Fix     = @(
                    "# These accounts explicitly allow RC4 (msDS-SupportedEncryptionTypes includes 0x4 + AES)"
                    "# After July 2026 they will be the only accounts still able to obtain RC4 tickets"
                    "# To harden: remove RC4 and set AES-only:"
                    "Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                    "Set-ADAccountPassword '<AccountName>' -Reset; klist purge"
                    "# Test application access - if it breaks, re-add RC4 exception and plan vendor upgrade"
                )
            }
        }

        if ($results.Accounts.TotalDESEnabled -gt 0) {
            $warnings++
            $desNames = ($results.Accounts.DESEnabledAccounts | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] $($results.Accounts.TotalDESEnabled) account(s) have DES encryption bits enabled (insecure, removed in Server 2025): $desNames"
                Fix     = @(
                    "# Remove DES bits and set AES-only:"
                    "Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                    "# 24 = 0x18 = AES128 + AES256 (recommended)"
                    "Set-ADAccountPassword '<AccountName>' -Reset; klist purge"
                )
            }
        }

        if ($results.Accounts.TotalStaleSvc -gt 0) {
            $warnings++
            $staleNames = ($results.Accounts.StaleServiceAccounts | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] $($results.Accounts.TotalStaleSvc) service account(s) have stale passwords (>365 days) with RC4: $staleNames"
                Fix     = @(
                    "# Reset password to generate fresh AES keys:"
                    "Set-ADAccountPassword '<ServiceAccount>' -Reset; klist purge"
                    "# Update services running under this account with the new password"
                )
            }
        }

        if ($results.Accounts.TotalMissingAES -gt 0) {
            $warnings++
            $missingNames = ($results.Accounts.MissingAESKeyAccounts | Select-Object -First 5 | ForEach-Object {
                    $logon = if ($_.LastLogon) { " (last logon: $($_.LastLogon.ToString('yyyy-MM-dd')))" } else { " (never logged on)" }
                    "$($_.Name)$logon"
                }) -join ', '
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] $($results.Accounts.TotalMissingAES) account(s) may be missing AES keys: $missingNames"
                Fix     = @(
                    "# Option 1: Reset password to generate AES keys:"
                    "Set-ADAccountPassword '<AccountName>' -Reset; klist purge"
                    "# Option 2: Use Fine-Grained Password Policy (FGPP) to re-use same password:"
                    "# Create a temporary FGPP that disables password history, apply to account,"
                    "# reset password with the same value, then remove the FGPP."
                    "# This avoids service disruption while generating AES keys."
                    "# If AES is still not used after password reset, explicitly set AES:"
                    "Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                    "Set-ADAccountPassword '<AccountName>' -Reset; klist purge"
                )
            }
        }

        # DeepScan recommendations
        if ($results.Accounts.TotalDeepScanRC4OnlyUsers -gt 0) {
            $criticalIssues++
            $dsNames = ($results.Accounts.DeepScanRC4OnlyUsers | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "CRITICAL"
                Message = "[$($results.Domain)] [DeepScan] $($results.Accounts.TotalDeepScanRC4OnlyUsers) user account(s) have RC4-only encryption: $dsNames"
                Fix     = @(
                    "Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                    "Set-ADAccountPassword '<AccountName>' -Reset; klist purge"
                )
            }
        }

        if ($results.Accounts.TotalDeepScanDESOnlyUsers -gt 0) {
            $criticalIssues++
            $dsNames = ($results.Accounts.DeepScanDESOnlyUsers | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "CRITICAL"
                Message = "[$($results.Domain)] [DeepScan] $($results.Accounts.TotalDeepScanDESOnlyUsers) user account(s) have DES-only encryption: $dsNames"
                Fix     = @(
                    "Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                    "Set-ADAccountPassword '<AccountName>' -Reset; klist purge"
                )
            }
        }

        if ($results.Accounts.TotalDeepScanDESEnabledUsers -gt 0) {
            $warnings++
            $dsNames = ($results.Accounts.DeepScanDESEnabledUsers | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] [DeepScan] $($results.Accounts.TotalDeepScanDESEnabledUsers) user account(s) have DES bits enabled alongside AES: $dsNames"
                Fix     = @(
                    "# Remove DES bits and set AES-only:"
                    "Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                )
            }
        }

        if ($results.Accounts.TotalDeepScanRC4ExceptionUsers -gt 0) {
            $warnings++
            $dsNames = ($results.Accounts.DeepScanRC4ExceptionUsers | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] [DeepScan] $($results.Accounts.TotalDeepScanRC4ExceptionUsers) user account(s) have explicit RC4 exception: $dsNames"
                Fix     = @(
                    "# Remove RC4 when possible:"
                    "Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                    "Set-ADAccountPassword '<AccountName>' -Reset; klist purge"
                )
            }
        }

        if ($results.Accounts.DeepScanComputersOSDefault -gt 0) {
            $warnings++
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] [DeepScan] $($results.Accounts.DeepScanComputersOSDefault) computer(s) have OS-default encryption (0x1C = RC4+AES) - deploy AES-only GPO"
                Fix     = @(
                    "# Deploy domain-level GPO:"
                    "# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options"
                    "# 'Network security: Configure encryption types allowed for Kerberos' = AES128_HMAC_SHA1 + AES256_HMAC_SHA1 + Future encryption types"
                )
            }
        }

        if ($results.Accounts.TotalDeepScanComputersProblematic -gt 0) {
            $warnings++
            $dsNames = ($results.Accounts.DeepScanComputersProblematic | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] [DeepScan] $($results.Accounts.TotalDeepScanComputersProblematic) computer(s) have non-default RC4/DES encryption: $dsNames"
                Fix     = @(
                    "# Investigate each computer and update to AES-only:"
                    "Set-ADComputer '<ComputerName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                )
            }
        }
    }

    # Check KDC registry
    if ($results.KdcRegistry) {
        if ($results.KdcRegistry.DefaultDomainSupportedEncTypes.Status -eq "CRITICAL") {
            $criticalIssues++
            $results.Recommendations += @{
                Level   = "CRITICAL"
                Message = "[$($results.Domain)] DefaultDomainSupportedEncTypes does NOT include AES"
                Fix     = @(
                    "# On each DC, update the registry to include AES:"
                    "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'DefaultDomainSupportedEncTypes' -Value 24 -Type DWord"
                    "# 24 = 0x18 = AES128 + AES256 (AES-only, recommended)"
                    "# For per-account RC4 exceptions: set msDS-SupportedEncryptionTypes=0x1C on the account, NOT domain-wide"
                )
            }
        }
        if ($results.KdcRegistry.RC4DefaultDisablementPhase.Status -in @("NOT SET", "WARNING")) {
            $warnings++
            $currentPhase = $results.KdcRegistry.RC4DefaultDisablementPhase.Value
            $phaseMsg = if ($results.KdcRegistry.RC4DefaultDisablementPhase.Status -eq "NOT SET") {
                "RC4DefaultDisablementPhase not set"
            }
            elseif ($currentPhase -eq 0) {
                "RC4DefaultDisablementPhase = 0 (not active)"
            }
            else {
                "RC4DefaultDisablementPhase = $currentPhase"
            }

            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] $phaseMsg"
                Fix     = @(
                    "# Step 1: Deploy January 2026+ security updates on all DCs"
                    "# Step 2: Enable KDCSVC audit events (System log events 201-209):"
                    "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'RC4DefaultDisablementPhase' -Value 1 -Type DWord"
                    "# Step 3: Monitor KDCSVC events and remediate any RC4 dependencies"
                    "# Step 4: When audit events are clear, enable Enforcement mode (value 2)"
                )
            }
        }
    }

    # Check KDCSVC events (CVE-2026-20833)
    if ($results.KdcSvcEvents -and $results.KdcSvcEvents.TotalEvents -gt 0) {
        $warnings++
        $eventSummary = ($results.KdcSvcEvents.EventCounts.GetEnumerator() | ForEach-Object { "Event $($_.Key): $($_.Value)" }) -join ', '
        $results.Recommendations += @{
            Level   = "WARNING"
            Message = "[$($results.Domain)] KDCSVC events detected - RC4 risks exist (CVE-2026-20833): $eventSummary"
            Fix     = @(
                "# Review KDCSVC events 201-209 in System event log on each DC"
                "# For accounts triggering events 201-203 (audit), set AES-only first:"
                "Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=24}"
                "# 24 = 0x18 = AES128 + AES256 (recommended)"
                "Set-ADAccountPassword '<AccountName>' -Reset; klist purge"
                "# If AES breaks the application, fall back to explicit RC4 exception:"
                "# Set-ADUser '<AccountName>' -Replace @{'msDS-SupportedEncryptionTypes'=0x1C}"
                "# Then set RC4DefaultDisablementPhase = 2 when no more audit events appear"
            )
        }
    }

    # Check audit policy
    if ($results.AuditPolicy -and $results.AuditPolicy.Status -eq "CRITICAL") {
        $warnings++
        $results.Recommendations += @{
            Level   = "WARNING"
            Message = "[$($results.Domain)] Kerberos auditing is NOT enabled - event log results may be incomplete"
            Fix     = @(
                "# Enable on each DC (or via GPO):"
                "auditpol /set /subcategory:""Kerberos Authentication Service"" /success:enable /failure:enable"
                "auditpol /set /subcategory:""Kerberos Service Ticket Operations"" /success:enable /failure:enable"
            )
        }
    }

    # Determine overall status
    if ($criticalIssues -gt 0) {
        $results.OverallStatus = "CRITICAL"
        Write-Finding -Status "CRITICAL" -Message "Critical security issues detected requiring immediate attention"
    }
    elseif ($warnings -gt 0) {
        $results.OverallStatus = "WARNING"
        Write-Finding -Status "WARNING" -Message "Security warnings detected - remediation recommended"
    }
    else {
        $results.OverallStatus = "OK"
        Write-Finding -Status "OK" -Message "No DES/RC4 usage detected - environment is secure"
    }

    # Display recommendations with inline fix commands
    if ($results.Recommendations.Count -gt 0) {
        Write-Host "`n  Recommendations & Remediation:" -ForegroundColor Yellow
        foreach ($rec in $results.Recommendations) {
            $recColor = if ($rec.Level -eq "CRITICAL") { "Red" } else { "Yellow" }
            Write-Host "    $([char]0x2022) $($rec.Level): $($rec.Message)" -ForegroundColor $recColor
            if ($rec.Fix) {
                foreach ($fixLine in $rec.Fix) {
                    if ($fixLine -match '^#') {
                        Write-Host "      $fixLine" -ForegroundColor Gray
                    }
                    else {
                        Write-Host "      PS> $fixLine" -ForegroundColor Green
                    }
                }
                Write-Host ""
            }
        }
    }

    # Check for event log access issues
    if ($results.EventLogs -and $results.EventLogs.FailedDCs.Count -gt 0) {
        Write-Host "`n  $([char]0x26A0)  Note: Event log data is incomplete due to $($results.EventLogs.FailedDCs.Count) DC(s) being inaccessible" -ForegroundColor Yellow
        Write-Host "  Review the detailed troubleshooting guidance in the Event Log Analysis section above" -ForegroundColor Yellow
    }

    # 6. Display Summary Tables
    Show-AssessmentSummary -Results $results

    # 7. Manual Validation Guidance (if requested)
    if ($IncludeGuidance) {
        Show-ManualValidationGuidance
    }
    else {
        Write-Host "`n  $([System.Char]::ConvertFromUtf32(0x1F4A1)) Tip: Use -IncludeGuidance for the full reference manual (audit setup, SIEM queries, KRBTGT rotation, July 2026 timeline)." -ForegroundColor Cyan
    }

    # 8. Export Results (if requested)
    if ($ExportResults) {
        Write-Section "Exporting Results"

        # Create Exports folder if it doesn't exist
        $exportFolder = Join-Path -Path $PWD -ChildPath "Exports"
        if (-not (Test-Path -Path $exportFolder)) {
            New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            Write-Finding -Status "INFO" -Message "Created export folder: $exportFolder"
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $domain = $results.Domain -replace '\.', '_'

        # Export JSON
        $jsonPath = Join-Path -Path $exportFolder -ChildPath "DES_RC4_Assessment_${domain}_${timestamp}.json"
        $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Finding -Status "OK" -Message "JSON export: $jsonPath"

        # Export CSV summary
        $csvPath = Join-Path -Path $exportFolder -ChildPath "DES_RC4_Assessment_${domain}_${timestamp}.csv"
        $csvData = @()

        # Add DC details
        foreach ($dc in $results.DomainControllers.Details) {
            $csvData += [PSCustomObject]@{
                Type             = "Domain Controller"
                Name             = $dc.Name
                Status           = $dc.Status
                EncryptionTypes  = $dc.EncryptionTypes
                EncryptionValue  = $dc.EncryptionValue
                LastLogon        = ''
                LastLogonDaysAgo = ''
            }
        }

        # Add AzureADKerberos if present
        if ($results.DomainControllers.AzureADKerberos) {
            $aadK = $results.DomainControllers.AzureADKerberos
            $csvData += [PSCustomObject]@{
                Type             = "Entra Kerberos Proxy"
                Name             = $aadK.Name
                Status           = $aadK.Status
                EncryptionTypes  = $aadK.EncryptionTypes
                EncryptionValue  = $aadK.EncryptionValue
                LastLogon        = ''
                LastLogonDaysAgo = ''
            }
        }

        # Add trust details
        foreach ($trust in $results.Trusts.Details) {
            $csvData += [PSCustomObject]@{
                Type             = "Trust"
                Name             = $trust.Name
                Status           = $trust.Status
                EncryptionTypes  = $trust.EncryptionTypes
                EncryptionValue  = $trust.EncryptionValue
                LastLogon        = ''
                LastLogonDaysAgo = ''
            }
        }

        # Add KRBTGT details
        if ($results.Accounts) {
            $csvData += [PSCustomObject]@{
                Type             = "KRBTGT"
                Name             = "krbtgt"
                Status           = "$($results.Accounts.KRBTGT.Status) (Password age: $($results.Accounts.KRBTGT.PasswordAgeDays) days)"
                EncryptionTypes  = $results.Accounts.KRBTGT.EncryptionTypes
                EncryptionValue  = $results.Accounts.KRBTGT.EncryptionValue
                LastLogon        = ''
                LastLogonDaysAgo = ''
            }

            # Add DES flag accounts
            foreach ($acct in $results.Accounts.DESFlagAccounts) {
                $csvData += [PSCustomObject]@{
                    Type             = "DES Flag Account"
                    Name             = $acct.Name
                    Status           = "USE_DES_KEY_ONLY"
                    EncryptionTypes  = $acct.EncryptionTypes
                    EncryptionValue  = $acct.EncryptionValue
                    LastLogon        = if ($acct.LastLogon) { $acct.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    LastLogonDaysAgo = $acct.LastLogonDaysAgo
                }
            }

            # Add RC4/DES-only service accounts
            foreach ($svc in $results.Accounts.RC4OnlyServiceAccounts) {
                $csvData += [PSCustomObject]@{
                    Type             = $svc.Type
                    Name             = $svc.Name
                    Status           = "$($svc.Type) (Password age: $($svc.PasswordAgeDays) days)"
                    EncryptionTypes  = $svc.EncryptionTypes
                    EncryptionValue  = $svc.EncryptionValue
                    LastLogon        = if ($svc.LastLogon) { $svc.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    LastLogonDaysAgo = $svc.LastLogonDaysAgo
                }
            }

            # Add RC4-only MSAs
            foreach ($msa in $results.Accounts.RC4OnlyMSAs) {
                $csvData += [PSCustomObject]@{
                    Type             = "RC4-Only $($msa.Type)"
                    Name             = $msa.Name
                    Status           = "RC4-Only"
                    EncryptionTypes  = $msa.EncryptionTypes
                    EncryptionValue  = $msa.EncryptionValue
                    LastLogon        = if ($msa.LastLogon) { $msa.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    LastLogonDaysAgo = $msa.LastLogonDaysAgo
                }
            }

            # Add DES-enabled accounts
            foreach ($des in $results.Accounts.DESEnabledAccounts) {
                $csvData += [PSCustomObject]@{
                    Type             = "DES-Enabled $($des.AccountType)"
                    Name             = $des.Name
                    Status           = "DES bits enabled (insecure)"
                    EncryptionTypes  = $des.EncryptionTypes
                    EncryptionValue  = $des.EncryptionValue
                    LastLogon        = if ($des.LastLogon) { $des.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    LastLogonDaysAgo = $des.LastLogonDaysAgo
                }
            }

            # Add RC4 exception accounts
            foreach ($exc in $results.Accounts.RC4ExceptionAccounts) {
                $excType = if ($exc.AccountType) { "RC4 Exception $($exc.AccountType)" } else { 'RC4 Exception' }
                $csvData += [PSCustomObject]@{
                    Type             = $excType
                    Name             = $exc.Name
                    Status           = "Explicit RC4 exception (review and remove RC4 when possible)"
                    EncryptionTypes  = $exc.EncryptionTypes
                    EncryptionValue  = $exc.EncryptionValue
                    LastLogon        = if ($exc.LastLogon) { $exc.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    LastLogonDaysAgo = $exc.LastLogonDaysAgo
                }
            }

            # Add accounts missing AES keys
            foreach ($acct in $results.Accounts.MissingAESKeyAccounts) {
                $csvData += [PSCustomObject]@{
                    Type             = "Missing AES Keys"
                    Name             = $acct.Name
                    Status           = "Password age: $($acct.PasswordAgeDays) days"
                    EncryptionTypes  = "Not Set"
                    EncryptionValue  = $null
                    LastLogon        = if ($acct.LastLogon) { $acct.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    LastLogonDaysAgo = $acct.LastLogonDaysAgo
                }
            }

            # Add DeepScan user accounts
            foreach ($u in $results.Accounts.DeepScanRC4OnlyUsers) {
                $csvData += [PSCustomObject]@{
                    Type             = "DeepScan RC4-Only User"
                    Name             = $u.Name
                    Status           = "RC4-Only (no SPN)"
                    EncryptionTypes  = $u.EncryptionTypes
                    EncryptionValue  = $u.EncryptionValue
                    LastLogon        = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    LastLogonDaysAgo = $u.LastLogonDaysAgo
                }
            }
            foreach ($u in $results.Accounts.DeepScanDESOnlyUsers) {
                $csvData += [PSCustomObject]@{
                    Type             = "DeepScan DES-Only User"
                    Name             = $u.Name
                    Status           = "DES-Only (no SPN)"
                    EncryptionTypes  = $u.EncryptionTypes
                    EncryptionValue  = $u.EncryptionValue
                    LastLogon        = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    LastLogonDaysAgo = $u.LastLogonDaysAgo
                }
            }
            foreach ($u in $results.Accounts.DeepScanDESEnabledUsers) {
                $csvData += [PSCustomObject]@{
                    Type             = "DeepScan DES-Enabled User"
                    Name             = $u.Name
                    Status           = "DES bits enabled alongside AES"
                    EncryptionTypes  = $u.EncryptionTypes
                    EncryptionValue  = $u.EncryptionValue
                    LastLogon        = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    LastLogonDaysAgo = $u.LastLogonDaysAgo
                }
            }
            foreach ($u in $results.Accounts.DeepScanRC4ExceptionUsers) {
                $csvData += [PSCustomObject]@{
                    Type             = "DeepScan RC4 Exception User"
                    Name             = $u.Name
                    Status           = "Explicit RC4 exception (no SPN)"
                    EncryptionTypes  = $u.EncryptionTypes
                    EncryptionValue  = $u.EncryptionValue
                    LastLogon        = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    LastLogonDaysAgo = $u.LastLogonDaysAgo
                }
            }

            # Add DeepScan problematic computers
            foreach ($c in $results.Accounts.DeepScanComputersProblematic) {
                $csvData += [PSCustomObject]@{
                    Type             = "DeepScan Problematic Computer"
                    Name             = $c.Name
                    Status           = "Non-default RC4/DES encryption"
                    EncryptionTypes  = $c.EncryptionTypes
                    EncryptionValue  = $c.EncryptionValue
                    LastLogon        = if ($c.LastLogon) { $c.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    LastLogonDaysAgo = $c.LastLogonDaysAgo
                }
            }

            # Add DeepScan OS-default computer summary
            if ($results.Accounts.DeepScanComputersOSDefault -gt 0) {
                $csvData += [PSCustomObject]@{
                    Type             = "DeepScan OS-Default Computers"
                    Name             = "(summary)"
                    Status           = "$($results.Accounts.DeepScanComputersOSDefault) computer(s) with 0x1C - deploy AES-only GPO"
                    EncryptionTypes  = "RC4_HMAC_MD5, AES128-HMAC, AES256-HMAC"
                    EncryptionValue  = 0x1C
                    LastLogon        = ''
                    LastLogonDaysAgo = ''
                }
            }
        }

        # Add KDC registry data
        if ($results.KdcRegistry) {
            $csvData += [PSCustomObject]@{
                Type             = "KDC Registry"
                Name             = "DefaultDomainSupportedEncTypes"
                Status           = $results.KdcRegistry.DefaultDomainSupportedEncTypes.Status
                EncryptionTypes  = if ($results.KdcRegistry.DefaultDomainSupportedEncTypes.Types) { $results.KdcRegistry.DefaultDomainSupportedEncTypes.Types } else { "Not Set" }
                EncryptionValue  = $results.KdcRegistry.DefaultDomainSupportedEncTypes.Value
                LastLogon        = ''
                LastLogonDaysAgo = ''
            }
            $csvData += [PSCustomObject]@{
                Type             = "KDC Registry"
                Name             = "RC4DefaultDisablementPhase"
                Status           = $results.KdcRegistry.RC4DefaultDisablementPhase.Status
                EncryptionTypes  = "N/A"
                EncryptionValue  = $results.KdcRegistry.RC4DefaultDisablementPhase.Value
                LastLogon        = ''
                LastLogonDaysAgo = ''
            }
        }

        # Add KDCSVC event data (CVE-2026-20833)
        if ($results.KdcSvcEvents -and $results.KdcSvcEvents.TotalEvents -gt 0) {
            foreach ($kvp in $results.KdcSvcEvents.EventCounts.GetEnumerator()) {
                $csvData += [PSCustomObject]@{
                    Type             = "KDCSVC Event (CVE-2026-20833)"
                    Name             = "Event ID $($kvp.Key)"
                    Status           = $results.KdcSvcEvents.Status
                    EncryptionTypes  = "N/A"
                    EncryptionValue  = $kvp.Value
                    LastLogon        = ''
                    LastLogonDaysAgo = ''
                }
            }
        }

        $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Finding -Status "OK" -Message "CSV export: $csvPath"

        # Export guidance text file (when both -ExportResults and -IncludeGuidance are used)
        if ($IncludeGuidance) {
            $guidancePath = Join-Path -Path $exportFolder -ChildPath "DES_RC4_Guidance_${domain}_${timestamp}.txt"
            $assessmentDateStr = if ($results.AssessmentDate) { $results.AssessmentDate.ToString('yyyy-MM-dd HH:mm:ss') } else { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
            $guidanceText = Get-GuidancePlainText -Domain $results.Domain -AssessmentDate $assessmentDateStr -Version $script:Version
            $guidanceText | Out-File -FilePath $guidancePath -Encoding UTF8
            Write-Finding -Status "OK" -Message "Guidance export: $guidancePath"
        }
    }

    # Final summary
    Write-Header "Assessment Complete" -Color "Cyan"

    Write-Host "`n$([System.Char]::ConvertFromUtf32(0x1F4CA)) Summary:" -ForegroundColor Cyan
    Write-Host "  $([char]0x2022) Domain: $($results.Domain)" -ForegroundColor White
    $displayDate = if ($results.AssessmentDate) { $results.AssessmentDate.ToString('yyyy-MM-dd HH:mm:ss') } else { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
    Write-Host "  $([char]0x2022) Assessment Date: $displayDate" -ForegroundColor White
    Write-Host "  $([char]0x2022) Overall Status: " -NoNewline -ForegroundColor White

    $statusColor = switch ($results.OverallStatus) {
        "OK" { "Green" }
        "WARNING" { "Yellow" }
        "CRITICAL" { "Red" }
        default { "Gray" }
    }
    Write-Host $results.OverallStatus -ForegroundColor $statusColor

    if (-not $AnalyzeEventLogs) {
        Write-Host "`n  $([System.Char]::ConvertFromUtf32(0x1F4A1)) For complete assessment, run with -AnalyzeEventLogs to detect actual DES/RC4 usage" -ForegroundColor Cyan
    }

    # Return results object for use by Assess-ADForest.ps1
    return $results
}
catch {
    Write-Finding -Status "CRITICAL" -Message "Assessment failed: $($_.Exception.Message)"
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}

#endregion







}

