<#
.SYNOPSIS
  Fast and accurate DES/RC4 Kerberos encryption assessment for Active Directory.

.DESCRIPTION
  This script provides a streamlined assessment of DES and RC4 encryption usage in Active Directory
  based on post-November 2022 Microsoft updates and real-world Kerberos ticket analysis.
  
  Key features:
  - Fast DC-level assessment (no full computer object enumeration)
  - Event log analysis for actual DES/RC4 ticket usage (Event IDs 4768/4769)
  - Post-Nov 2022 logic: Trusts default to AES when msDS-SupportedEncryptionTypes is unset
  - KDC registry key assessment (DefaultDomainSupportedEncTypes, RC4DefaultDisablementPhase)
  - Kerberos audit policy pre-check before event log analysis
  - KRBTGT account password age and encryption type assessment
  - Service account (SPN) and gMSA/sMSA RC4/DES encryption detection
  - Accounts with USE_DES_KEY_ONLY UserAccountControl flag detection
  - Accounts missing AES keys (password set before DFL raised to 2008)
  - Realistic computer object assessment: Only flags actual RC4 fallback scenarios
  - Actionable guidance for manual validation and monitoring setup
  - July 2026 RC4 removal timeline and explicit RC4 exception workflow
  - Performance optimized for large forests (<5 minutes vs 5+ hours)
  
  Post-November 2022 Update Logic:
  - Computer objects: RC4 fallback only occurs when msDS-SupportedEncryptionTypes is set to non-zero 
    value on client AND DC does not have AES configured. If DC has AES via GPO, clients inherit AES.
  - Trusts: Default to AES when msDS-SupportedEncryptionTypes is not set (0 or empty).
  - Focus on actual usage via Event Logs rather than theoretical fallback scenarios.

.PARAMETER Domain
  Target domain to assess. If not specified, uses current domain.

.PARAMETER Server
  Specific domain controller to query. If not specified, uses any available DC.

.PARAMETER AnalyzeEventLogs
  Analyze DC event logs for actual DES/RC4 ticket usage (Event IDs 4768/4769).
  This provides real-world usage data vs theoretical risk.

.PARAMETER EventLogHours
  Number of hours of event logs to analyze. Default: 24 hours.

.PARAMETER ExportResults
  Export assessment results to JSON and CSV files.

.PARAMETER IncludeGuidance
  Include detailed guidance for manual validation steps and monitoring setup.

.PARAMETER QuickScan
  Fast scan mode - DC/GPO/Trust assessment only, no event log analysis.

.EXAMPLE
  .\RC4_DES_Assessment.ps1
  Run quick assessment of current domain (DC, GPO, Trust configuration only).

.EXAMPLE
  .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 48
  Full assessment including 48 hours of event log analysis for actual DES/RC4 usage.

.EXAMPLE
  .\RC4_DES_Assessment.ps1 -Domain contoso.com -AnalyzeEventLogs -ExportResults
  Assess specific domain with event analysis and export results.

.EXAMPLE
  .\RC4_DES_Assessment.ps1 -IncludeGuidance
  Run assessment and display detailed guidance for manual validation.

.NOTES
  Author: Jan Tiedemann
  Version: 2.3.0
  Requirements: 
    - PowerShell 5.1 or later
    - Active Directory PowerShell module (RSAT-AD-PowerShell)
    - Group Policy PowerShell module (GPMC)
    - Domain Admin or equivalent read permissions
    - For Event Log analysis: Event log access on DCs
  
  Based on Microsoft guidance:
  - November 2022 OOB Updates (CVE-2022-37966, CVE-2022-37967)
  - KB5021131: Managing Kerberos protocol changes
  - January 2026 security updates (RC4 disablement Phase 1)
  - July 2026 RC4 full removal from KDC path
  - Microsoft Kerberos-Crypto scripts: https://github.com/microsoft/Kerberos-Crypto

.LINK
  https://techcommunity.microsoft.com/blog/askds/what-happened-to-kerberos-authentication-after-installing-the-november-2022oob-u/3696351
  
.LINK
  https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797
#>

[CmdletBinding(DefaultParameterSetName = 'QuickScan')]
param(
    [Parameter(ParameterSetName = 'QuickScan')]
    [Parameter(ParameterSetName = 'FullScan')]
    [string]$Domain,
    
    [Parameter(ParameterSetName = 'QuickScan')]
    [Parameter(ParameterSetName = 'FullScan')]
    [string]$Server,
    
    [Parameter(ParameterSetName = 'FullScan', Mandatory = $true)]
    [switch]$AnalyzeEventLogs,
    
    [Parameter(ParameterSetName = 'FullScan')]
    [ValidateRange(1, 168)]
    [int]$EventLogHours = 24,
    
    [Parameter(ParameterSetName = 'QuickScan')]
    [Parameter(ParameterSetName = 'FullScan')]
    [switch]$ExportResults,
    
    [Parameter(ParameterSetName = 'QuickScan')]
    [Parameter(ParameterSetName = 'FullScan')]
    [switch]$IncludeGuidance,
    
    [Parameter(ParameterSetName = 'QuickScan')]
    [switch]$QuickScan
)

#Requires -Modules ActiveDirectory

# Configure console encoding for proper Unicode display (PowerShell 5.1 compatibility)
$originalOutputEncoding = [Console]::OutputEncoding
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $Host.UI.RawUI.OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
    # Silently continue if console encoding cannot be set (e.g., in ISE)
}

# Script version and metadata
$script:Version = "2.3.0"
$script:AssessmentTimestamp = Get-Date

#region Helper Functions

function Write-Header {
    param([string]$Title, [string]$Color = "Cyan")
    
    Write-Host "`n$("=" * 80)" -ForegroundColor $Color
    Write-Host $Title -ForegroundColor $Color
    Write-Host $("=" * 80) -ForegroundColor $Color
}

function Write-Section {
    param([string]$Title, [string]$Color = "Yellow")
    
    Write-Host "`n$Title" -ForegroundColor $Color
    Write-Host $("-" * 60) -ForegroundColor $Color
}

function Write-Finding {
    param(
        [string]$Status,  # OK, WARNING, CRITICAL, INFO
        [string]$Message,
        [string]$Detail = ""
    )
    
    $statusSymbol = switch ($Status) {
        "OK" { "$([char]0x2713)"; $color = "Green" }   # ✓ Check mark
        "WARNING" { "$([char]0x26A0) "; $color = "Yellow" } # ⚠ Warning sign
        "CRITICAL" { "$([char]0x2717)"; $color = "Red" }     # ✗ Cross mark
        "INFO" { "$([char]0x24D8) "; $color = "Cyan" }   # ⓘ Circled i (PS 5.1 compatible)
        default { "$([char]0x2022)"; $color = "White" }   # $([char]0x2022) Asterisk (ASCII)
    }
    
    Write-Host "$statusSymbol $Message" -ForegroundColor $color
    if ($Detail) {
        Write-Host "   $Detail" -ForegroundColor Gray
    }
}

function Get-EncryptionTypeString {
    param([int]$Value)
    
    if (-not $Value -or $Value -eq 0) {
        return "Not Set (Default)"
    }
    
    $types = @()
    if ($Value -band 0x1) { $types += "DES-CBC-CRC" }
    if ($Value -band 0x2) { $types += "DES-CBC-MD5" }
    if ($Value -band 0x4) { $types += "RC4-HMAC" }
    if ($Value -band 0x8) { $types += "AES128-HMAC" }
    if ($Value -band 0x10) { $types += "AES256-HMAC" }
    
    return ($types -join ", ")
}

function Get-TicketEncryptionType {
    param([int]$EncryptionType)
    
    # Event log encryption type values
    switch ($EncryptionType) {
        0x1 { return "DES-CBC-CRC" }
        0x3 { return "DES-CBC-MD5" }
        0x11 { return "AES128-HMAC-SHA1" }
        0x12 { return "AES256-HMAC-SHA1" }
        0x17 { return "RC4-HMAC" }
        0x18 { return "RC4-HMAC-EXP" }
        default { return "Unknown (0x$($EncryptionType.ToString('X')))" }
    }
}

#endregion

#region Assessment Functions

function Get-DomainControllerEncryption {
    param(
        [hashtable]$ServerParams
    )
    
    Write-Section "Domain Controller Encryption Configuration"
    
    $assessment = @{
        TotalDCs           = 0
        AESConfigured      = 0
        RC4Configured      = 0
        DESConfigured      = 0
        NotConfigured      = 0
        Details            = @()
        GPOConfigured      = $false
        GPOEncryptionTypes = $null
    }
    
    try {
        # Get domain info - ensure we query the correct domain
        if ($ServerParams.ContainsKey('Server')) {
            Write-Verbose "Attempting to contact DC: $($ServerParams['Server'])"
            try {
                $domainInfo = Get-ADDomain -Server $ServerParams['Server'] -ErrorAction Stop
            }
            catch {
                throw "Failed to contact Domain Controller '$($ServerParams['Server'])': $($_.Exception.Message)"
            }
        }
        else {
            $domainInfo = Get-ADDomain
        }
        $dcOU = "OU=Domain Controllers,$($domainInfo.DistinguishedName)"
        
        Write-Finding -Status "INFO" -Message "Analyzing domain: $($domainInfo.DNSRoot)"
        
        # Get all domain controllers
        $dcs = Get-ADComputer -SearchBase $dcOU -Filter * -Properties msDS-SupportedEncryptionTypes, OperatingSystem @ServerParams
        $assessment.TotalDCs = if ($dcs) { if ($dcs -is [array]) { $dcs.Count } else { 1 } } else { 0 }
        
        Write-Finding -Status "INFO" -Message "Found $($assessment.TotalDCs) Domain Controller(s)"
        
        # Analyze each DC
        foreach ($dc in $dcs) {
            $encValue = $dc.'msDS-SupportedEncryptionTypes'
            $encTypes = Get-EncryptionTypeString -Value $encValue
            
            $dcInfo = @{
                Name            = $dc.Name
                EncryptionValue = $encValue
                EncryptionTypes = $encTypes
                OS              = $dc.OperatingSystem
                Status          = "Unknown"
            }
            
            if (-not $encValue -or $encValue -eq 0) {
                $assessment.NotConfigured++
                $dcInfo.Status = "Not Configured (Inherits from GPO)"
            }
            elseif ($encValue -band 0x18) {
                # AES128 or AES256
                $assessment.AESConfigured++
                $dcInfo.Status = "AES Configured"
                
                if ($encValue -band 0x4) {
                    # Also has RC4
                    $assessment.RC4Configured++
                    $dcInfo.Status += " + RC4"
                }
                if ($encValue -band 0x3) {
                    # Also has DES
                    $assessment.DESConfigured++
                    $dcInfo.Status += " + DES"
                }
            }
            elseif ($encValue -band 0x4) {
                # RC4 only
                $assessment.RC4Configured++
                $dcInfo.Status = "RC4 Only"
            }
            elseif ($encValue -band 0x3) {
                # DES only
                $assessment.DESConfigured++
                $dcInfo.Status = "DES Only"
            }
            
            $assessment.Details += $dcInfo
        }
        
        # Check GPO configuration
        Write-Host "`n  Checking GPO Kerberos encryption policy..." -ForegroundColor Cyan
        
        try {
            # Try to get GPO inheritance for DC OU
            $gpoInheritance = Get-GPInheritance -Target $dcOU -Domain $domainInfo.DNSRoot @ServerParams -ErrorAction Stop
            
            if ($gpoInheritance -and $gpoInheritance.GpoLinks) {
                foreach ($gpoLink in $gpoInheritance.GpoLinks) {
                    if ($gpoLink.Enabled) {
                        $gpoReport = Get-GPOReport -Guid $gpoLink.GpoId -ReportType Xml -Domain $domainInfo.DNSRoot @ServerParams -ErrorAction SilentlyContinue
                        
                        if ($gpoReport -and $gpoReport -match "Configure encryption types allowed for Kerberos") {
                            $assessment.GPOConfigured = $true
                            
                            # Extract encryption value from GPO
                            if ($gpoReport -match 'name="Configure encryption types allowed for Kerberos".*?<decimal value="(\d+)"') {
                                $assessment.GPOEncryptionTypes = [int]$matches[1]
                            }
                            
                            Write-Finding -Status "OK" -Message "GPO '$($gpoLink.DisplayName)' configures Kerberos encryption" `
                                -Detail "Encryption types: $(Get-EncryptionTypeString -Value $assessment.GPOEncryptionTypes)"
                            break
                        }
                    }
                }
            }
        }
        catch {
            Write-Finding -Status "WARNING" -Message "Could not retrieve GPO information: $($_.Exception.Message)"
        }
        
        # Display summary
        Write-Host ""
        Write-Finding -Status "INFO" -Message "Domain Controller Summary:"
        Write-Host "  $([char]0x2022) Total DCs: $($assessment.TotalDCs)" -ForegroundColor White
        Write-Host "  $([char]0x2022) AES Configured: $($assessment.AESConfigured)" -ForegroundColor $(if ($assessment.AESConfigured -eq $assessment.TotalDCs) { "Green" } else { "Yellow" })
        Write-Host "  $([char]0x2022) RC4 Configured: $($assessment.RC4Configured)" -ForegroundColor $(if ($assessment.RC4Configured -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  $([char]0x2022) DES Configured: $($assessment.DESConfigured)" -ForegroundColor $(if ($assessment.DESConfigured -gt 0) { "Red" } else { "Green" })
        Write-Host "  $([char]0x2022) Not Configured (GPO Inherited): $($assessment.NotConfigured)" -ForegroundColor Cyan
        
        # Display individual DC details
        if ($assessment.Details.Count -gt 0) {
            Write-Host "`n  Individual DC Status:" -ForegroundColor Cyan
            foreach ($dcInfo in $assessment.Details) {
                $statusColor = switch -Regex ($dcInfo.Status) {
                    "AES Configured$" { "Green" }
                    "RC4" { "Yellow" }
                    "DES" { "Red" }
                    default { "Cyan" }
                }
                Write-Host "    $([char]0x2022) $($dcInfo.Name): $($dcInfo.Status)" -ForegroundColor $statusColor
                if ($dcInfo.EncryptionValue) {
                    Write-Host "      Types: $($dcInfo.EncryptionTypes)" -ForegroundColor Gray
                }
            }
        }
        
        # Assessment
        if ($assessment.GPOConfigured -and ($assessment.GPOEncryptionTypes -band 0x18)) {
            Write-Finding -Status "OK" -Message "Domain Controllers are configured for AES encryption via GPO"
            if ($assessment.NotConfigured -gt 0) {
                Write-Finding -Status "INFO" -Message "$($assessment.NotConfigured) DC(s) inherit AES settings from GPO (this is normal)"
            }
        }
        elseif ($assessment.AESConfigured -eq $assessment.TotalDCs) {
            Write-Finding -Status "OK" -Message "All Domain Controllers have AES encryption configured"
        }
        else {
            Write-Finding -Status "WARNING" -Message "Not all Domain Controllers have AES encryption configured"
        }
        
        if ($assessment.DESConfigured -gt 0) {
            Write-Finding -Status "CRITICAL" -Message "$($assessment.DESConfigured) DC(s) have DES encryption enabled - immediate remediation required"
        }
        
        if ($assessment.RC4Configured -gt 0) {
            Write-Finding -Status "WARNING" -Message "$($assessment.RC4Configured) DC(s) have RC4 encryption enabled"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        # Extract DC name from error message if it mentions "Failed to contact Domain Controller"
        if ($errorMsg -match "Failed to contact Domain Controller '([^']+)'") {
            Write-Finding -Status "CRITICAL" -Message $errorMsg
        }
        elseif ($ServerParams.ContainsKey('Server')) {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing Domain Controllers (Attempted DC: $($ServerParams['Server'])): $errorMsg"
        }
        else {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing Domain Controllers: $errorMsg"
        }
    }
    
    return $assessment
}

function Get-TrustEncryptionAssessment {
    param(
        [hashtable]$ServerParams
    )
    
    Write-Section "Trust Encryption Assessment (Post-November 2022 Logic)"
    
    $assessment = @{
        TotalTrusts = 0
        ExplicitAES = 0
        DefaultAES  = 0  # Post-Nov 2022: Empty/0 = AES default
        RC4Risk     = 0
        DESRisk     = 0
        Details     = @()
    }
    
    try {
        # Get domain info - ensure we query the correct domain
        if ($ServerParams.ContainsKey('Server')) {
            Write-Verbose "Attempting to contact DC: $($ServerParams['Server'])"
            try {
                $domainInfo = Get-ADDomain -Server $ServerParams['Server'] -ErrorAction Stop
            }
            catch {
                throw "Failed to contact Domain Controller '$($ServerParams['Server'])': $($_.Exception.Message)"
            }
        }
        else {
            $domainInfo = Get-ADDomain
        }
        $trusts = Get-ADTrust -Filter * @ServerParams -Properties msDS-SupportedEncryptionTypes, TrustDirection, TrustType
        
        if (-not $trusts) {
            Write-Finding -Status "INFO" -Message "No trusts found in domain: $($domainInfo.DNSRoot)"
            return $assessment
        }
        
        $assessment.TotalTrusts = if ($trusts -is [array]) { $trusts.Count } else { 1 }
        Write-Finding -Status "INFO" -Message "Found $($assessment.TotalTrusts) trust(s)"
        
        foreach ($trust in $trusts) {
            $encValue = $trust.'msDS-SupportedEncryptionTypes'
            $encTypes = Get-EncryptionTypeString -Value $encValue
            
            $trustInfo = @{
                Name                 = $trust.Name
                Direction            = $trust.TrustDirection
                Type                 = $trust.TrustType
                EncryptionValue      = $encValue
                EncryptionTypes      = $encTypes
                Status               = "Unknown"
                PostNov2022Compliant = $false
            }
            
            # Post-November 2022 logic: Trusts default to AES when not set
            if (-not $encValue -or $encValue -eq 0) {
                $assessment.DefaultAES++
                $trustInfo.Status = "AES (Default - Post-Nov 2022)"
                $trustInfo.PostNov2022Compliant = $true
                Write-Finding -Status "OK" -Message "Trust '$($trust.Name)': Uses AES by default (msDS-SupportedEncryptionTypes not set)"
            }
            elseif ($encValue -band 0x18) {
                # Explicit AES
                $assessment.ExplicitAES++
                $trustInfo.Status = "AES (Explicitly Configured)"
                $trustInfo.PostNov2022Compliant = $true
                
                if ($encValue -band 0x4) {
                    # Also has RC4
                    $assessment.RC4Risk++
                    $trustInfo.Status += " + RC4 Enabled"
                    Write-Finding -Status "WARNING" -Message "Trust '$($trust.Name)': AES configured but RC4 also enabled" `
                        -Detail "Encryption: $encTypes"
                }
                else {
                    Write-Finding -Status "OK" -Message "Trust '$($trust.Name)': AES explicitly configured"
                }
                
                if ($encValue -band 0x3) {
                    # Also has DES
                    $assessment.DESRisk++
                    $trustInfo.Status += " + DES Enabled"
                    Write-Finding -Status "CRITICAL" -Message "Trust '$($trust.Name)': DES encryption enabled" `
                        -Detail "Encryption: $encTypes"
                }
            }
            elseif ($encValue -band 0x4) {
                # RC4 only
                $assessment.RC4Risk++
                $trustInfo.Status = "RC4 Only"
                Write-Finding -Status "WARNING" -Message "Trust '$($trust.Name)': RC4 only - consider removing explicit setting to use AES default"
            }
            elseif ($encValue -band 0x3) {
                # DES only
                $assessment.DESRisk++
                $trustInfo.Status = "DES Only"
                Write-Finding -Status "CRITICAL" -Message "Trust '$($trust.Name)': DES only - immediate remediation required"
            }
            
            $assessment.Details += $trustInfo
        }
        
        # Summary
        Write-Host ""
        Write-Finding -Status "INFO" -Message "Trust Assessment Summary:"
        Write-Host "  $([char]0x2022) Total Trusts: $($assessment.TotalTrusts)" -ForegroundColor White
        Write-Host "  $([char]0x2022) AES Default (not set): $($assessment.DefaultAES)" -ForegroundColor Green
        Write-Host "  $([char]0x2022) AES Explicit: $($assessment.ExplicitAES)" -ForegroundColor Green
        Write-Host "  $([char]0x2022) RC4 Risk: $($assessment.RC4Risk)" -ForegroundColor $(if ($assessment.RC4Risk -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  $([char]0x2022) DES Risk: $($assessment.DESRisk)" -ForegroundColor $(if ($assessment.DESRisk -gt 0) { "Red" } else { "Green" })
        
        Write-Host "`n  $([System.Char]::ConvertFromUtf32(0x1F4D8)) Post-November 2022 Update:" -ForegroundColor Cyan
        Write-Host "  When msDS-SupportedEncryptionTypes is not set (0 or empty) on trusts," -ForegroundColor Gray
        Write-Host "  they default to AES encryption. No action needed for these trusts." -ForegroundColor Gray
    }
    catch {
        $errorMsg = $_.Exception.Message
        # Extract DC name from error message if it mentions "Failed to contact Domain Controller"
        if ($errorMsg -match "Failed to contact Domain Controller '([^']+)'") {
            Write-Finding -Status "CRITICAL" -Message $errorMsg
        }
        elseif ($ServerParams.ContainsKey('Server')) {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing trusts (Attempted DC: $($ServerParams['Server'])): $errorMsg"
        }
        else {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing trusts: $errorMsg"
        }
    }
    
    return $assessment
}

function Get-KdcRegistryAssessment {
    param(
        [hashtable]$ServerParams
    )
    
    Write-Section "KDC Registry Configuration Assessment"
    
    $assessment = @{
        DefaultDomainSupportedEncTypes = @{
            Configured  = $false
            Value       = $null
            Types       = ""
            IncludesRC4 = $false
            IncludesAES = $false
            Status      = "Unknown"
        }
        RC4DefaultDisablementPhase     = @{
            Configured = $false
            Value      = $null
            Status     = "Unknown"
        }
        QueriedDCs                     = @()
        FailedDCs                      = @()
        Details                        = @()
    }
    
    try {
        # Get domain info
        if ($ServerParams.ContainsKey('Server')) {
            try {
                $domainInfo = Get-ADDomain -Server $ServerParams['Server'] -ErrorAction Stop
            }
            catch {
                throw "Failed to contact Domain Controller '$($ServerParams['Server'])': $($_.Exception.Message)"
            }
        }
        else {
            $domainInfo = Get-ADDomain
        }
        
        # Get all DCs
        $dcOU = "OU=Domain Controllers,$($domainInfo.DistinguishedName)"
        $dcs = Get-ADComputer -SearchBase $dcOU -Filter * -Properties DNSHostName @ServerParams
        
        if (-not $dcs) {
            Write-Finding -Status "WARNING" -Message "No Domain Controllers found for registry assessment"
            return $assessment
        }
        
        Write-Finding -Status "INFO" -Message "Checking KDC registry keys on $(@($dcs).Count) Domain Controller(s)"
        
        $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
        
        foreach ($dc in @($dcs)) {
            $dcName = if ($dc.DNSHostName) { $dc.DNSHostName } else { "$($dc.Name).$($domainInfo.DNSRoot)" }
            Write-Host "  $([char]0x2022) Querying $dcName..." -ForegroundColor Cyan
            
            try {
                $regValues = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    param($Path)
                    $result = @{ DefaultDomainSupportedEncTypes = $null; RC4DefaultDisablementPhase = $null }
                    try {
                        $val = Get-ItemProperty -Path $Path -Name 'DefaultDomainSupportedEncTypes' -ErrorAction SilentlyContinue
                        if ($val) { $result.DefaultDomainSupportedEncTypes = $val.DefaultDomainSupportedEncTypes }
                    }
                    catch {}
                    try {
                        $val = Get-ItemProperty -Path $Path -Name 'RC4DefaultDisablementPhase' -ErrorAction SilentlyContinue
                        if ($val) { $result.RC4DefaultDisablementPhase = $val.RC4DefaultDisablementPhase }
                    }
                    catch {}
                    $result
                } -ArgumentList $regPath -ErrorAction Stop
                
                $assessment.QueriedDCs += $dcName
                
                $dcDetail = @{
                    Name                           = $dcName
                    DefaultDomainSupportedEncTypes = $regValues.DefaultDomainSupportedEncTypes
                    RC4DefaultDisablementPhase     = $regValues.RC4DefaultDisablementPhase
                }
                $assessment.Details += $dcDetail
                
                # Process DefaultDomainSupportedEncTypes
                if ($null -ne $regValues.DefaultDomainSupportedEncTypes) {
                    $encVal = [int]$regValues.DefaultDomainSupportedEncTypes
                    $assessment.DefaultDomainSupportedEncTypes.Configured = $true
                    $assessment.DefaultDomainSupportedEncTypes.Value = $encVal
                    $assessment.DefaultDomainSupportedEncTypes.Types = Get-EncryptionTypeString -Value $encVal
                    $assessment.DefaultDomainSupportedEncTypes.IncludesRC4 = [bool]($encVal -band 0x4)
                    $assessment.DefaultDomainSupportedEncTypes.IncludesAES = [bool]($encVal -band 0x18)
                    
                    Write-Host "    DefaultDomainSupportedEncTypes: $encVal ($(Get-EncryptionTypeString -Value $encVal))" -ForegroundColor Gray
                }
                
                # Process RC4DefaultDisablementPhase
                if ($null -ne $regValues.RC4DefaultDisablementPhase) {
                    $assessment.RC4DefaultDisablementPhase.Configured = $true
                    $assessment.RC4DefaultDisablementPhase.Value = [int]$regValues.RC4DefaultDisablementPhase
                    
                    Write-Host "    RC4DefaultDisablementPhase: $($regValues.RC4DefaultDisablementPhase)" -ForegroundColor Gray
                }
            }
            catch {
                $assessment.FailedDCs += @{ Name = $dcName; Error = $_.Exception.Message }
                Write-Host "    $([char]0x26A0) Could not query registry on $dcName" -ForegroundColor Yellow
            }
        }
        
        # Assess DefaultDomainSupportedEncTypes
        if ($assessment.DefaultDomainSupportedEncTypes.Configured) {
            if (-not $assessment.DefaultDomainSupportedEncTypes.IncludesAES) {
                $assessment.DefaultDomainSupportedEncTypes.Status = "CRITICAL"
                Write-Finding -Status "CRITICAL" -Message "DefaultDomainSupportedEncTypes does NOT include AES" `
                    -Detail "Value: $($assessment.DefaultDomainSupportedEncTypes.Value) ($($assessment.DefaultDomainSupportedEncTypes.Types))"
            }
            elseif ($assessment.DefaultDomainSupportedEncTypes.IncludesRC4) {
                $assessment.DefaultDomainSupportedEncTypes.Status = "OK"
                Write-Finding -Status "INFO" -Message "DefaultDomainSupportedEncTypes includes RC4 (needed for explicit RC4 exceptions post-July 2026)" `
                    -Detail "Value: $($assessment.DefaultDomainSupportedEncTypes.Value) ($($assessment.DefaultDomainSupportedEncTypes.Types))"
            }
            else {
                $assessment.DefaultDomainSupportedEncTypes.Status = "OK"
                Write-Finding -Status "OK" -Message "DefaultDomainSupportedEncTypes is AES-only" `
                    -Detail "Value: $($assessment.DefaultDomainSupportedEncTypes.Value) ($($assessment.DefaultDomainSupportedEncTypes.Types))"
            }
        }
        else {
            $assessment.DefaultDomainSupportedEncTypes.Status = "NOT SET"
            Write-Finding -Status "INFO" -Message "DefaultDomainSupportedEncTypes registry key is not set (uses OS defaults)"
        }
        
        # Assess RC4DefaultDisablementPhase
        if ($assessment.RC4DefaultDisablementPhase.Configured) {
            $phase = $assessment.RC4DefaultDisablementPhase.Value
            switch ($phase) {
                0 {
                    $assessment.RC4DefaultDisablementPhase.Status = "WARNING"
                    Write-Finding -Status "WARNING" -Message "RC4DefaultDisablementPhase = 0 (RC4 disablement NOT active)" `
                        -Detail "Set to 1 to begin RC4 disablement on this DC"
                }
                1 {
                    $assessment.RC4DefaultDisablementPhase.Status = "OK"
                    Write-Finding -Status "OK" -Message "RC4DefaultDisablementPhase = 1 (RC4 disablement active)" `
                        -Detail "RC4 is disabled for accounts without explicit RC4 in msDS-SupportedEncryptionTypes"
                }
                default {
                    $assessment.RC4DefaultDisablementPhase.Status = "INFO"
                    Write-Finding -Status "INFO" -Message "RC4DefaultDisablementPhase = $phase" `
                        -Detail "Unexpected value - check Microsoft documentation for current phase definitions"
                }
            }
        }
        else {
            $assessment.RC4DefaultDisablementPhase.Status = "NOT SET"
            Write-Finding -Status "WARNING" -Message "RC4DefaultDisablementPhase registry key is not set" `
                -Detail "Deploy January 2026+ security updates and set RC4DefaultDisablementPhase = 1 on all DCs"
        }
        
        if ($assessment.FailedDCs.Count -gt 0) {
            Write-Host "`n  $([char]0x26A0) Could not query registry on $($assessment.FailedDCs.Count) DC(s) - WinRM may not be enabled" -ForegroundColor Yellow
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -match "Failed to contact Domain Controller '([^']+)'") {
            Write-Finding -Status "CRITICAL" -Message $errorMsg
        }
        else {
            Write-Finding -Status "WARNING" -Message "Error checking KDC registry: $errorMsg"
        }
    }
    
    return $assessment
}

function Get-AuditPolicyCheck {
    param(
        [hashtable]$ServerParams
    )
    
    Write-Section "Kerberos Audit Policy Verification"
    
    $assessment = @{
        KerberosAuthServiceEnabled = $null    # $true, $false, or $null if unknown
        KerberosTicketOpsEnabled   = $null
        Status                     = "Unknown"
        QueriedDC                  = $null
    }
    
    try {
        # Get domain info
        if ($ServerParams.ContainsKey('Server')) {
            try {
                $domainInfo = Get-ADDomain -Server $ServerParams['Server'] -ErrorAction Stop
            }
            catch {
                throw "Failed to contact Domain Controller '$($ServerParams['Server'])': $($_.Exception.Message)"
            }
        }
        else {
            $domainInfo = Get-ADDomain
        }
        
        # Query first available DC
        $dcOU = "OU=Domain Controllers,$($domainInfo.DistinguishedName)"
        $dc = Get-ADComputer -SearchBase $dcOU -Filter * -Properties DNSHostName @ServerParams | Select-Object -First 1
        
        if (-not $dc) {
            Write-Finding -Status "WARNING" -Message "No Domain Controller found for audit policy check"
            return $assessment
        }
        
        $dcName = if ($dc.DNSHostName) { $dc.DNSHostName } else { "$($dc.Name).$($domainInfo.DNSRoot)" }
        $assessment.QueriedDC = $dcName
        
        Write-Finding -Status "INFO" -Message "Checking Kerberos audit policy on $dcName"
        
        try {
            $auditResult = Invoke-Command -ComputerName $dcName -ScriptBlock {
                $output = auditpol /get /subcategory:"Kerberos Authentication Service" 2>&1
                $authService = $output | Out-String
                $output2 = auditpol /get /subcategory:"Kerberos Service Ticket Operations" 2>&1
                $ticketOps = $output2 | Out-String
                @{
                    AuthService = $authService
                    TicketOps   = $ticketOps
                }
            } -ErrorAction Stop
            
            # Parse audit policy results
            $assessment.KerberosAuthServiceEnabled = $auditResult.AuthService -match 'Success and Failure|Success|Failure'
            $assessment.KerberosTicketOpsEnabled = $auditResult.TicketOps -match 'Success and Failure|Success|Failure'
            
            if ($assessment.KerberosAuthServiceEnabled -and $assessment.KerberosTicketOpsEnabled) {
                $assessment.Status = "OK"
                Write-Finding -Status "OK" -Message "Kerberos auditing is enabled (Authentication Service + Ticket Operations)"
            }
            elseif (-not $assessment.KerberosAuthServiceEnabled -and -not $assessment.KerberosTicketOpsEnabled) {
                $assessment.Status = "CRITICAL"
                Write-Finding -Status "CRITICAL" -Message "Kerberos auditing is NOT enabled - event log analysis will return no results" `
                    -Detail "Enable via: auditpol /set /subcategory:""Kerberos Authentication Service"" /success:enable /failure:enable"
                Write-Host "    Also run: auditpol /set /subcategory:""Kerberos Service Ticket Operations"" /success:enable /failure:enable" -ForegroundColor Gray
            }
            else {
                $assessment.Status = "WARNING"
                if (-not $assessment.KerberosAuthServiceEnabled) {
                    Write-Finding -Status "WARNING" -Message "Kerberos Authentication Service auditing is NOT enabled"
                }
                if (-not $assessment.KerberosTicketOpsEnabled) {
                    Write-Finding -Status "WARNING" -Message "Kerberos Service Ticket Operations auditing is NOT enabled"
                }
            }
        }
        catch {
            $assessment.Status = "UNKNOWN"
            Write-Finding -Status "WARNING" -Message "Could not check audit policy on $dcName`: $($_.Exception.Message)" `
                -Detail "Verify manually: auditpol /get /subcategory:""Kerberos Authentication Service"""
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $assessment.Status = "UNKNOWN"
        Write-Finding -Status "WARNING" -Message "Error checking audit policy: $errorMsg"
    }
    
    return $assessment
}

function Get-EventLogEncryptionAnalysis {
    param(
        [hashtable]$ServerParams,
        [int]$Hours = 24
    )
    
    Write-Section "Event Log Analysis - Actual DES/RC4 Usage"
    
    $assessment = @{
        EventsAnalyzed = 0
        DESTickets     = 0
        RC4Tickets     = 0
        AESTickets     = 0
        UnknownTickets = 0
        TimeRange      = $Hours
        DESAccounts    = @()
        RC4Accounts    = @()
        Details        = @()
        FailedDCs      = @()  # Track DCs that couldn't be queried
        QueriedDCs     = @()  # Track DCs that were successfully queried
    }
    
    try {
        $startTime = (Get-Date).AddHours(-$Hours)
        
        Write-Finding -Status "INFO" -Message "Analyzing last $Hours hours of Kerberos ticket events"
        Write-Host "  Time range: $($startTime.ToString('yyyy-MM-dd HH:mm')) to $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Gray
        
        # Get domain controllers - ensure we query the correct domain
        if ($ServerParams.ContainsKey('Server')) {
            Write-Verbose "Attempting to contact DC: $($ServerParams['Server'])"
            try {
                $domainInfo = Get-ADDomain -Server $ServerParams['Server'] -ErrorAction Stop
            }
            catch {
                throw "Failed to contact Domain Controller '$($ServerParams['Server'])': $($_.Exception.Message)"
            }
        }
        else {
            $domainInfo = Get-ADDomain
        }
        
        # Get ALL domain controllers for comprehensive event log analysis
        Write-Verbose "Discovering all Domain Controllers in $($domainInfo.DNSRoot)"
        $dcOU = "OU=Domain Controllers,$($domainInfo.DistinguishedName)"
        $dcs = Get-ADComputer -SearchBase $dcOU -Filter * -Properties DNSHostName @ServerParams
        
        if (-not $dcs) {
            Write-Finding -Status "WARNING" -Message "No Domain Controllers found for event log analysis"
            return $assessment
        }
        
        Write-Finding -Status "INFO" -Message "Querying event logs from $($dcs.Count) Domain Controller(s) in $($domainInfo.DNSRoot)"
        Write-Host "  Note: Using WinRM (PowerShell Remoting) for event log queries" -ForegroundColor Gray
        Write-Host "  If this fails, ensure WinRM is enabled on DCs: Enable-PSRemoting -Force" -ForegroundColor Gray
        
        foreach ($dc in $dcs) {
            $dcName = if ($dc.DNSHostName) { $dc.DNSHostName } else { "$($dc.Name).$($domainInfo.DNSRoot)" }
            Write-Host "  $([char]0x2022) Querying $dcName..." -ForegroundColor Cyan
            
            try {
                # Test connectivity first
                if (-not (Test-Connection -ComputerName $dcName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
                    Write-Host "    $([char]0x26A0) Cannot reach $dcName - skipping" -ForegroundColor Yellow
                    $assessment.FailedDCs += @{
                        Name  = $dcName
                        Error = "Network unreachable - ping failed"
                    }
                    continue
                }
                
                # Event ID 4768 = TGT Request, 4769 = Service Ticket Request
                # TicketEncryptionType field shows actual encryption used
                $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4768 or EventID=4769) and TimeCreated[timediff(@SystemTime) &lt;= $($Hours * 3600000)]]]
    </Select>
  </Query>
</QueryList>
"@
                
                # Try Invoke-Command first (WinRM - more reliable for remote DCs)
                $events = $null
                try {
                    $events = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        param($FilterXml, $MaxEvents)
                        Get-WinEvent -FilterXml $FilterXml -MaxEvents $MaxEvents -ErrorAction Stop
                    } -ArgumentList $filterXml, 1000 -ErrorAction Stop
                }
                catch {
                    # WinRM failed, try RPC as fallback
                    Write-Host "    $([char]0x26A0) WinRM unavailable on $dcName, trying RPC..." -ForegroundColor DarkYellow
                    
                    try {
                        $events = Get-WinEvent -ComputerName $dcName -FilterXml $filterXml -MaxEvents 1000 -ErrorAction Stop
                    }
                    catch {
                        throw $_
                    }
                }
                
                if (-not $events) {
                    Write-Host "    $([char]0x24D8) No events found on $dcName" -ForegroundColor Gray
                    $assessment.QueriedDCs += $dcName  # Still track as successfully queried
                    continue
                }
                
                if ($events) {
                    Write-Host "    $([char]0x2713) Retrieved $($events.Count) events from $dcName" -ForegroundColor Green
                    $assessment.EventsAnalyzed += $events.Count
                    $assessment.QueriedDCs += $dcName  # Track successfully queried DC
                    
                    foreach ($event in $events) {
                        # Handle both direct and remoted event objects
                        $eventXml = if ($event.ToXml) { 
                            $event.ToXml() 
                        } 
                        else { 
                            # For deserialized objects from Invoke-Command, reconstruct XML manually
                            $event | ConvertTo-Xml -As String -Depth 3
                        }
                        
                        $xml = [xml]$eventXml
                        $eventData = @{}
                        
                        # Handle both native EventLogRecord and deserialized objects
                        if ($xml.Event.EventData.Data) {
                            foreach ($data in $xml.Event.EventData.Data) {
                                $eventData[$data.Name] = $data.'#text'
                            }
                        }
                        elseif ($event.Properties) {
                            # Fallback: Use Properties collection for deserialized events
                            # Event 4768/4769 property indexes (may vary, use properties by name if available)
                            if ($event.Properties.Count -ge 10) {
                                $eventData['TargetUserName'] = $event.Properties[0].Value
                                $eventData['TicketEncryptionType'] = $event.Properties[7].Value
                            }
                        }
                        
                        if (-not $eventData['TicketEncryptionType']) {
                            continue
                        }
                        
                        $encType = [int]$eventData['TicketEncryptionType']
                        $account = $eventData['TargetUserName']
                        
                        # Categorize by encryption type
                        switch ($encType) {
                            { $_ -in @(0x1, 0x3) } {
                                # DES
                                $assessment.DESTickets++
                                if ($account -and $account -notin $assessment.DESAccounts) {
                                    $assessment.DESAccounts += $account
                                }
                            }
                            0x17 {
                                # RC4
                                $assessment.RC4Tickets++
                                if ($account -and $account -notin $assessment.RC4Accounts) {
                                    $assessment.RC4Accounts += $account
                                }
                            }
                            { $_ -in @(0x11, 0x12) } {
                                # AES
                                $assessment.AESTickets++
                            }
                            default {
                                $assessment.UnknownTickets++
                            }
                        }
                    }
                }
            }
            catch {
                $errorMsg = $_.Exception.Message
                $assessment.FailedDCs += @{
                    Name  = $dcName
                    Error = $errorMsg
                }
                
                if ($errorMsg -match "WinRM|WSMan|PowerShell Remoting") {
                    Write-Host "    $([char]0x2717) WinRM not available on $dcName" -ForegroundColor Red
                    Write-Host "    Enable with: Invoke-Command -ComputerName $dcName -ScriptBlock { Enable-PSRemoting -Force }" -ForegroundColor Gray
                }
                elseif ($errorMsg -match "RPC server|network path") {
                    Write-Host "    $([char]0x2717) RPC/Network error on $dcName" -ForegroundColor Red
                    Write-Host "    Both WinRM (5985) and RPC (135) failed. Check firewall or run locally on DC" -ForegroundColor Gray
                }
                elseif ($errorMsg -match "Access is denied|unauthorized") {
                    Write-Host "    $([char]0x2717) Access denied on $dcName" -ForegroundColor Red
                    Write-Host "    Ensure you have Event Log Readers permissions or are Domain Admin" -ForegroundColor Gray
                }
                else {
                    Write-Host "    $([char]0x2717) Failed to query $dcName`: $errorMsg" -ForegroundColor Red
                }
            }
        }
        
        # Display results
        Write-Host ""
        Write-Finding -Status "INFO" -Message "Event Log Analysis Results:"
        Write-Host "  $([char]0x2022) Events Analyzed: $($assessment.EventsAnalyzed)" -ForegroundColor White
        Write-Host "  $([char]0x2022) AES Tickets: $($assessment.AESTickets)" -ForegroundColor Green
        Write-Host "  $([char]0x2022) RC4 Tickets: $($assessment.RC4Tickets)" -ForegroundColor $(if ($assessment.RC4Tickets -gt 0) { "Red" } else { "Green" })
        Write-Host "  $([char]0x2022) DES Tickets: $($assessment.DESTickets)" -ForegroundColor $(if ($assessment.DESTickets -gt 0) { "Red" } else { "Green" })
        
        if ($assessment.RC4Tickets -gt 0) {
            Write-Finding -Status "CRITICAL" -Message "RC4 tickets detected in active use!"
            Write-Host "  Unique accounts using RC4: $($assessment.RC4Accounts.Count)" -ForegroundColor Red
            
            if ($assessment.RC4Accounts.Count -le 10) {
                Write-Host "  RC4 accounts:" -ForegroundColor Yellow
                foreach ($acct in $assessment.RC4Accounts) {
                    Write-Host "    - $acct" -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Finding -Status "OK" -Message "No RC4 tickets detected in last $Hours hours"
        }
        
        if ($assessment.DESTickets -gt 0) {
            Write-Finding -Status "CRITICAL" -Message "DES tickets detected in active use!"
            Write-Host "  Unique accounts using DES: $($assessment.DESAccounts.Count)" -ForegroundColor Red
        }
        else {
            Write-Finding -Status "OK" -Message "No DES tickets detected in last $Hours hours"
        }
        
        # Display event log query failures summary if any
        if ($assessment.FailedDCs.Count -gt 0) {
            Write-Host "`n  $([char]0x26A0)  Event Log Query Failures:" -ForegroundColor Yellow
            Write-Host "  $($assessment.FailedDCs.Count) Domain Controller(s) could not be queried for event logs`n" -ForegroundColor Yellow
            
            foreach ($failed in $assessment.FailedDCs) {
                Write-Host "  $([char]0x2022) $($failed.Name): $($failed.Error)" -ForegroundColor DarkYellow
            }
            
            Write-Host "`n  $([System.Char]::ConvertFromUtf32(0x1F527)) How to fix remote event log access issues:" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  Option 1: Enable WinRM (Recommended)" -ForegroundColor White
            Write-Host "  $([string]([char]0x2500) * 40)" -ForegroundColor DarkGray
            Write-Host "  Run on each failed DC:" -ForegroundColor Gray
            Write-Host "  PS> Enable-PSRemoting -Force" -ForegroundColor Green
            Write-Host "  PS> Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force" -ForegroundColor Green
            Write-Host "  PS> Restart-Service WinRM" -ForegroundColor Green
            Write-Host ""
            Write-Host "  Or via Group Policy (for all DCs):" -ForegroundColor Gray
            Write-Host "  Computer Configuration > Policies > Administrative Templates" -ForegroundColor Gray
            Write-Host "  > Windows Components > Windows Remote Management (WinRM) > WinRM Service" -ForegroundColor Gray
            Write-Host "  - Enable 'Allow remote server management through WinRM'" -ForegroundColor Gray
            Write-Host "  - IPv4 filter: * (or specific IPs)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Option 2: Configure Firewall for RPC" -ForegroundColor White
            Write-Host "  $([string]([char]0x2500) * 40)" -ForegroundColor DarkGray
            Write-Host "  Required ports:" -ForegroundColor Gray
            Write-Host "  - TCP 135 (RPC Endpoint Mapper)" -ForegroundColor Gray
            Write-Host "  - TCP 49152-65535 (Dynamic RPC ports)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Windows Firewall rule:" -ForegroundColor Gray
            Write-Host "  PS> Enable-NetFirewallRule -DisplayGroup 'Remote Event Log Management'" -ForegroundColor Green
            Write-Host ""
            Write-Host "  Option 3: Run Locally on DC" -ForegroundColor White
            Write-Host "  $([string]([char]0x2500) * 40)" -ForegroundColor DarkGray
            Write-Host "  Copy script to DC and run:" -ForegroundColor Gray
            Write-Host "  PS> .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours $Hours" -ForegroundColor Green
            Write-Host ""
            Write-Host "  Option 4: Verify Permissions" -ForegroundColor White
            Write-Host "  $([string]([char]0x2500) * 40)" -ForegroundColor DarkGray
            Write-Host "  Add your account to 'Event Log Readers' group on DCs:" -ForegroundColor Gray
            Write-Host "  PS> Add-ADGroupMember -Identity 'Event Log Readers' -Members 'YourAccount'" -ForegroundColor Green
            Write-Host "  Or use Domain Admin account (has all required permissions)" -ForegroundColor Gray
            Write-Host ""
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        # Extract DC name from error message if it mentions "Failed to contact Domain Controller"
        if ($errorMsg -match "Failed to contact Domain Controller '([^']+)'") {
            Write-Finding -Status "CRITICAL" -Message $errorMsg
        }
        elseif ($ServerParams.ContainsKey('Server')) {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing event logs (Attempted DC: $($ServerParams['Server'])): $errorMsg"
        }
        else {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing event logs: $errorMsg"
        }
    }
    
    return $assessment
}

function Get-AccountEncryptionAssessment {
    param(
        [hashtable]$ServerParams
    )
    
    Write-Section "KRBTGT & Service Account Encryption Assessment"
    
    $assessment = @{
        KRBTGT                 = @{
            PasswordAgeDays = 0
            PasswordLastSet = $null
            EncryptionValue = $null
            EncryptionTypes = ""
            Status          = "Unknown"
        }
        DESFlagAccounts        = @()
        RC4OnlyServiceAccounts = @()
        RC4OnlyMSAs            = @()
        StaleServiceAccounts   = @()
        MissingAESKeyAccounts  = @()
        TotalDESFlag           = 0
        TotalRC4OnlySvc        = 0
        TotalRC4OnlyMSA        = 0
        TotalStaleSvc          = 0
        TotalMissingAES        = 0
        Details                = @()
    }
    
    try {
        # Get domain info
        if ($ServerParams.ContainsKey('Server')) {
            Write-Verbose "Attempting to contact DC: $($ServerParams['Server'])"
            try {
                $domainInfo = Get-ADDomain -Server $ServerParams['Server'] -ErrorAction Stop
            }
            catch {
                throw "Failed to contact Domain Controller '$($ServerParams['Server'])': $($_.Exception.Message)"
            }
        }
        else {
            $domainInfo = Get-ADDomain
        }
        
        Write-Finding -Status "INFO" -Message "Analyzing accounts in domain: $($domainInfo.DNSRoot)"
        
        # ────────────────────────────────────────────────
        # 1. KRBTGT Account Assessment
        # ────────────────────────────────────────────────
        Write-Host "`n  Checking KRBTGT account..." -ForegroundColor Cyan
        
        try {
            $krbtgt = Get-ADUser -Identity "krbtgt" `
                -Properties pwdLastSet, 'msDS-SupportedEncryptionTypes', PasswordLastSet, WhenChanged @ServerParams -ErrorAction Stop
            
            $pwdLastSet = $krbtgt.PasswordLastSet
            if (-not $pwdLastSet -and $krbtgt.pwdLastSet) {
                $pwdLastSet = [DateTime]::FromFileTime($krbtgt.pwdLastSet)
            }
            
            $passwordAgeDays = if ($pwdLastSet) { ((Get-Date) - $pwdLastSet).Days } else { -1 }
            $encValue = $krbtgt.'msDS-SupportedEncryptionTypes'
            $encTypes = Get-EncryptionTypeString -Value $encValue
            
            $assessment.KRBTGT.PasswordAgeDays = $passwordAgeDays
            $assessment.KRBTGT.PasswordLastSet = $pwdLastSet
            $assessment.KRBTGT.EncryptionValue = $encValue
            $assessment.KRBTGT.EncryptionTypes = $encTypes
            
            # Assess KRBTGT password age
            if ($passwordAgeDays -lt 0) {
                $assessment.KRBTGT.Status = "UNKNOWN"
                Write-Finding -Status "WARNING" -Message "KRBTGT password last set date could not be determined"
            }
            elseif ($passwordAgeDays -gt 365) {
                $assessment.KRBTGT.Status = "CRITICAL"
                Write-Finding -Status "CRITICAL" -Message "KRBTGT password is $passwordAgeDays days old (last set: $($pwdLastSet.ToString('yyyy-MM-dd')))" `
                    -Detail "Microsoft recommends rotating KRBTGT password at least every 180 days. Stale KRBTGT may retain old RC4-only keys."
            }
            elseif ($passwordAgeDays -gt 180) {
                $assessment.KRBTGT.Status = "WARNING"
                Write-Finding -Status "WARNING" -Message "KRBTGT password is $passwordAgeDays days old (last set: $($pwdLastSet.ToString('yyyy-MM-dd')))" `
                    -Detail "Consider rotating KRBTGT password (recommended: every 180 days)"
            }
            else {
                $assessment.KRBTGT.Status = "OK"
                Write-Finding -Status "OK" -Message "KRBTGT password age: $passwordAgeDays days (last set: $($pwdLastSet.ToString('yyyy-MM-dd')))"
            }
            
            # Assess KRBTGT encryption types
            if ($encValue -and ($encValue -band 0x3) -and -not ($encValue -band 0x18)) {
                Write-Finding -Status "CRITICAL" -Message "KRBTGT has DES encryption configured without AES" `
                    -Detail "Encryption types: $encTypes (Value: 0x$($encValue.ToString('X')))"
            }
            elseif ($encValue -and ($encValue -band 0x4) -and -not ($encValue -band 0x18)) {
                Write-Finding -Status "CRITICAL" -Message "KRBTGT has RC4-only encryption configured" `
                    -Detail "Encryption types: $encTypes (Value: 0x$($encValue.ToString('X')))"
            }
            elseif (-not $encValue -or $encValue -eq 0) {
                Write-Finding -Status "INFO" -Message "KRBTGT msDS-SupportedEncryptionTypes: Not Set (uses domain defaults)" `
                    -Detail "Encryption keys depend on domain functional level and when password was last set"
            }
            else {
                Write-Finding -Status "OK" -Message "KRBTGT encryption types: $encTypes"
            }
        }
        catch {
            Write-Finding -Status "WARNING" -Message "Could not query KRBTGT account: $($_.Exception.Message)"
        }
        
        # ────────────────────────────────────────────────
        # 2. Accounts with USE_DES_KEY_ONLY flag
        # ────────────────────────────────────────────────
        Write-Host "`n  Checking for accounts with USE_DES_KEY_ONLY flag..." -ForegroundColor Cyan
        
        try {
            # UAC bit 0x200000 = 2097152 = USE_DES_KEY_ONLY
            $desAccounts = Get-ADUser -Filter 'UserAccountControl -band 2097152' `
                -Properties UserAccountControl, 'msDS-SupportedEncryptionTypes', PasswordLastSet, ServicePrincipalName, Enabled @ServerParams -ErrorAction Stop
            
            if ($desAccounts) {
                $desList = @($desAccounts)
                $assessment.TotalDESFlag = $desList.Count
                
                foreach ($acct in $desList) {
                    $acctInfo = @{
                        Name            = $acct.SamAccountName
                        DN              = $acct.DistinguishedName
                        Enabled         = $acct.Enabled
                        PasswordLastSet = $acct.PasswordLastSet
                        EncryptionValue = $acct.'msDS-SupportedEncryptionTypes'
                        EncryptionTypes = Get-EncryptionTypeString -Value $acct.'msDS-SupportedEncryptionTypes'
                        HasSPN          = [bool]$acct.ServicePrincipalName
                        Flag            = "USE_DES_KEY_ONLY"
                    }
                    $assessment.DESFlagAccounts += $acctInfo
                }
                
                Write-Finding -Status "CRITICAL" -Message "$($desList.Count) account(s) have USE_DES_KEY_ONLY flag set in UserAccountControl" `
                    -Detail "These accounts are forced to use DES encryption - immediate remediation required"
                
                foreach ($acct in $assessment.DESFlagAccounts) {
                    $enabledStr = if ($acct.Enabled) { "Enabled" } else { "Disabled" }
                    Write-Host "    $([char]0x2022) $($acct.Name) ($enabledStr)" -ForegroundColor Red
                }
            }
            else {
                Write-Finding -Status "OK" -Message "No accounts have USE_DES_KEY_ONLY flag set"
            }
        }
        catch {
            Write-Finding -Status "WARNING" -Message "Could not query for DES flag accounts: $($_.Exception.Message)"
        }
        
        # ────────────────────────────────────────────────
        # 3. Service accounts with RC4/DES-only encryption
        # ────────────────────────────────────────────────
        Write-Host "`n  Checking service accounts (accounts with SPNs)..." -ForegroundColor Cyan
        
        try {
            # Get user accounts with SPNs (service accounts)
            $svcAccounts = Get-ADUser -Filter 'ServicePrincipalName -like "*"' `
                -Properties ServicePrincipalName, 'msDS-SupportedEncryptionTypes', PasswordLastSet, Enabled, DisplayName @ServerParams -ErrorAction Stop
            
            if ($svcAccounts) {
                $svcList = @($svcAccounts)
                Write-Finding -Status "INFO" -Message "Found $($svcList.Count) service account(s) with SPNs"
                
                foreach ($svc in $svcList) {
                    $encValue = $svc.'msDS-SupportedEncryptionTypes'
                    $pwdAge = if ($svc.PasswordLastSet) { ((Get-Date) - $svc.PasswordLastSet).Days } else { -1 }
                    
                    # Check for RC4-only (has RC4 bit but no AES bits)
                    if ($encValue -and ($encValue -band 0x4) -and -not ($encValue -band 0x18)) {
                        $svcInfo = @{
                            Name            = $svc.SamAccountName
                            DN              = $svc.DistinguishedName
                            Enabled         = $svc.Enabled
                            PasswordLastSet = $svc.PasswordLastSet
                            PasswordAgeDays = $pwdAge
                            EncryptionValue = $encValue
                            EncryptionTypes = Get-EncryptionTypeString -Value $encValue
                            SPNs            = ($svc.ServicePrincipalName | Select-Object -First 3) -join "; "
                            Type            = "RC4-Only Service Account"
                        }
                        $assessment.RC4OnlyServiceAccounts += $svcInfo
                    }
                    
                    # Check for DES-only (has DES bits but no AES bits)
                    if ($encValue -and ($encValue -band 0x3) -and -not ($encValue -band 0x18)) {
                        $svcInfo = @{
                            Name            = $svc.SamAccountName
                            DN              = $svc.DistinguishedName
                            Enabled         = $svc.Enabled
                            PasswordLastSet = $svc.PasswordLastSet
                            PasswordAgeDays = $pwdAge
                            EncryptionValue = $encValue
                            EncryptionTypes = Get-EncryptionTypeString -Value $encValue
                            SPNs            = ($svc.ServicePrincipalName | Select-Object -First 3) -join "; "
                            Type            = "DES-Only Service Account"
                        }
                        # Avoid duplicate if already caught by RC4 check (e.g., value 0x7 = DES+RC4)
                        if ($svc.SamAccountName -notin $assessment.RC4OnlyServiceAccounts.Name) {
                            $assessment.RC4OnlyServiceAccounts += $svcInfo
                        }
                    }
                    
                    # Check for stale password with RC4 enabled (>365 days old, RC4 bit set, account enabled)
                    if ($pwdAge -gt 365 -and $encValue -and ($encValue -band 0x4) -and $svc.Enabled) {
                        $svcInfo = @{
                            Name            = $svc.SamAccountName
                            DN              = $svc.DistinguishedName
                            Enabled         = $svc.Enabled
                            PasswordLastSet = $svc.PasswordLastSet
                            PasswordAgeDays = $pwdAge
                            EncryptionValue = $encValue
                            EncryptionTypes = Get-EncryptionTypeString -Value $encValue
                            SPNs            = ($svc.ServicePrincipalName | Select-Object -First 3) -join "; "
                            Type            = "Stale Password Service Account"
                        }
                        # Avoid duplicates with RC4-only list
                        if ($svc.SamAccountName -notin $assessment.StaleServiceAccounts.Name) {
                            $assessment.StaleServiceAccounts += $svcInfo
                        }
                    }
                }
                
                $assessment.TotalRC4OnlySvc = $assessment.RC4OnlyServiceAccounts.Count
                $assessment.TotalStaleSvc = $assessment.StaleServiceAccounts.Count
                
                if ($assessment.RC4OnlyServiceAccounts.Count -gt 0) {
                    Write-Finding -Status "CRITICAL" -Message "$($assessment.RC4OnlyServiceAccounts.Count) service account(s) have RC4/DES-only encryption configured"
                    foreach ($svc in $assessment.RC4OnlyServiceAccounts) {
                        $enabledStr = if ($svc.Enabled) { "Enabled" } else { "Disabled" }
                        Write-Host "    $([char]0x2022) $($svc.Name) ($enabledStr) - $($svc.EncryptionTypes)" -ForegroundColor Red
                        Write-Host "      SPNs: $($svc.SPNs)" -ForegroundColor Gray
                    }
                }
                else {
                    Write-Finding -Status "OK" -Message "No service accounts have RC4/DES-only encryption configured"
                }
                
                if ($assessment.StaleServiceAccounts.Count -gt 0) {
                    Write-Finding -Status "WARNING" -Message "$($assessment.StaleServiceAccounts.Count) service account(s) have stale passwords (>365 days) with RC4 enabled"
                    foreach ($svc in $assessment.StaleServiceAccounts) {
                        Write-Host "    $([char]0x2022) $($svc.Name) - Password age: $($svc.PasswordAgeDays) days, Types: $($svc.EncryptionTypes)" -ForegroundColor Yellow
                    }
                }
            }
            else {
                Write-Finding -Status "INFO" -Message "No service accounts with SPNs found (excluding computer accounts)"
            }
        }
        catch {
            Write-Finding -Status "WARNING" -Message "Could not query service accounts: $($_.Exception.Message)"
        }
        
        # ────────────────────────────────────────────────
        # 4. Managed Service Accounts (gMSA/sMSA)
        # ────────────────────────────────────────────────
        Write-Host "`n  Checking Managed Service Accounts (gMSA/sMSA)..." -ForegroundColor Cyan
        
        try {
            $msaAccounts = Get-ADServiceAccount -Filter * `
                -Properties 'msDS-SupportedEncryptionTypes', PasswordLastSet, Enabled, ServicePrincipalName, ObjectClass @ServerParams -ErrorAction Stop
            
            if ($msaAccounts) {
                $msaList = @($msaAccounts)
                Write-Finding -Status "INFO" -Message "Found $($msaList.Count) Managed Service Account(s)"
                
                foreach ($msa in $msaList) {
                    $encValue = $msa.'msDS-SupportedEncryptionTypes'
                    
                    # Check for RC4-only (has RC4 bit but no AES bits)
                    if ($encValue -and ($encValue -band 0x4) -and -not ($encValue -band 0x18)) {
                        $msaInfo = @{
                            Name            = $msa.SamAccountName
                            DN              = $msa.DistinguishedName
                            Enabled         = $msa.Enabled
                            PasswordLastSet = $msa.PasswordLastSet
                            EncryptionValue = $encValue
                            EncryptionTypes = Get-EncryptionTypeString -Value $encValue
                            ObjectClass     = $msa.ObjectClass
                            Type            = if ($msa.ObjectClass -eq 'msDS-GroupManagedServiceAccount') { "gMSA" } else { "sMSA" }
                        }
                        $assessment.RC4OnlyMSAs += $msaInfo
                    }
                }
                
                $assessment.TotalRC4OnlyMSA = $assessment.RC4OnlyMSAs.Count
                
                if ($assessment.RC4OnlyMSAs.Count -gt 0) {
                    Write-Finding -Status "WARNING" -Message "$($assessment.RC4OnlyMSAs.Count) Managed Service Account(s) have RC4-only encryption"
                    foreach ($msa in $assessment.RC4OnlyMSAs) {
                        Write-Host "    $([char]0x2022) $($msa.Name) ($($msa.Type)) - $($msa.EncryptionTypes)" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Finding -Status "OK" -Message "All Managed Service Accounts use AES or default encryption"
                }
            }
            else {
                Write-Finding -Status "INFO" -Message "No Managed Service Accounts found"
            }
        }
        catch {
            if ($_.Exception.Message -match "cmdlet.*not recognized|not loaded|is not recognized") {
                Write-Finding -Status "INFO" -Message "Get-ADServiceAccount not available - skipping MSA check"
            }
            else {
                Write-Finding -Status "WARNING" -Message "Could not query Managed Service Accounts: $($_.Exception.Message)"
            }
        }
        
        # ────────────────────────────────────────────────
        # 5. Accounts missing AES keys (password set before DFL 2008)
        # ────────────────────────────────────────────────
        Write-Host "`n  Checking for accounts missing AES keys..." -ForegroundColor Cyan
        
        try {
            # Determine when DFL was raised to 2008 (DFL >= Windows2008Domain means AES keys are generated on password set)
            # Accounts whose password was last set BEFORE the DFL was raised to 2008 won't have AES keys
            $dfl = $domainInfo.DomainMode
            $dflSupportsAES = $dfl -match '2008|2012|2016|Windows2008|Windows2012|Windows2016|2025'
            
            if ($dflSupportsAES) {
                # Find enabled user accounts with very old passwords that likely predate AES key generation
                # We look for accounts with msDS-SupportedEncryptionTypes = 0 or not set, AND password > 5 years old
                # These accounts may have been created before DFL was raised and never had password reset
                $fiveYearsAgo = (Get-Date).AddYears(-5)
                $oldAccounts = Get-ADUser -Filter { Enabled -eq $true -and PasswordLastSet -lt $fiveYearsAgo } `
                    -Properties 'msDS-SupportedEncryptionTypes', PasswordLastSet, ServicePrincipalName, WhenCreated @ServerParams -ErrorAction Stop
                
                if ($oldAccounts) {
                    $oldList = @($oldAccounts)
                    
                    foreach ($acct in $oldList) {
                        $encValue = $acct.'msDS-SupportedEncryptionTypes'
                        $pwdAge = if ($acct.PasswordLastSet) { ((Get-Date) - $acct.PasswordLastSet).Days } else { -1 }
                        
                        # Flag accounts where password hasn't been reset since before AES was available
                        # AND msDS-SupportedEncryptionTypes is not set (meaning no explicit AES bits)
                        if ((-not $encValue -or $encValue -eq 0) -and $pwdAge -gt 1825) {
                            $acctInfo = @{
                                Name            = $acct.SamAccountName
                                DN              = $acct.DistinguishedName
                                PasswordLastSet = $acct.PasswordLastSet
                                PasswordAgeDays = $pwdAge
                                WhenCreated     = $acct.WhenCreated
                                HasSPN          = [bool]$acct.ServicePrincipalName
                                Type            = "Missing AES Keys"
                            }
                            $assessment.MissingAESKeyAccounts += $acctInfo
                        }
                    }
                    
                    $assessment.TotalMissingAES = $assessment.MissingAESKeyAccounts.Count
                    
                    if ($assessment.MissingAESKeyAccounts.Count -gt 0) {
                        Write-Finding -Status "WARNING" -Message "$($assessment.MissingAESKeyAccounts.Count) account(s) may be missing AES keys (password not reset since DFL raised to 2008+)" `
                            -Detail "Reset password twice for these accounts to generate AES keys"
                        
                        $displayCount = [Math]::Min($assessment.MissingAESKeyAccounts.Count, 10)
                        foreach ($acct in $assessment.MissingAESKeyAccounts | Select-Object -First $displayCount) {
                            $spnStr = if ($acct.HasSPN) { " [HAS SPN]" } else { "" }
                            Write-Host "    $([char]0x2022) $($acct.Name) - Password age: $($acct.PasswordAgeDays) days$spnStr" -ForegroundColor Yellow
                        }
                        if ($assessment.MissingAESKeyAccounts.Count -gt 10) {
                            Write-Host "    ... and $($assessment.MissingAESKeyAccounts.Count - 10) more" -ForegroundColor Yellow
                        }
                    }
                    else {
                        Write-Finding -Status "OK" -Message "No accounts found with potentially missing AES keys"
                    }
                }
                else {
                    Write-Finding -Status "OK" -Message "No accounts found with passwords older than 5 years"
                }
            }
            else {
                Write-Finding -Status "WARNING" -Message "Domain functional level ($dfl) may not support AES key generation" `
                    -Detail "Raise DFL to Windows Server 2008 or higher to enable AES Kerberos keys"
            }
        }
        catch {
            Write-Finding -Status "WARNING" -Message "Could not check for accounts missing AES keys: $($_.Exception.Message)"
        }
        
        # ────────────────────────────────────────────────
        # Summary
        # ────────────────────────────────────────────────
        Write-Host ""
        Write-Finding -Status "INFO" -Message "Account Encryption Assessment Summary:"
        
        $krbtgtColor = switch ($assessment.KRBTGT.Status) {
            "OK" { "Green" }
            "WARNING" { "Yellow" }
            "CRITICAL" { "Red" }
            default { "Gray" }
        }
        Write-Host "  $([char]0x2022) KRBTGT Password Age: $($assessment.KRBTGT.PasswordAgeDays) days" -ForegroundColor $krbtgtColor
        Write-Host "  $([char]0x2022) USE_DES_KEY_ONLY Accounts: $($assessment.TotalDESFlag)" -ForegroundColor $(if ($assessment.TotalDESFlag -gt 0) { "Red" } else { "Green" })
        Write-Host "  $([char]0x2022) RC4/DES-Only Service Accounts: $($assessment.TotalRC4OnlySvc)" -ForegroundColor $(if ($assessment.TotalRC4OnlySvc -gt 0) { "Red" } else { "Green" })
        Write-Host "  $([char]0x2022) RC4-Only Managed Service Accounts: $($assessment.TotalRC4OnlyMSA)" -ForegroundColor $(if ($assessment.TotalRC4OnlyMSA -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  $([char]0x2022) Stale Password Service Accounts (>365d, RC4): $($assessment.TotalStaleSvc)" -ForegroundColor $(if ($assessment.TotalStaleSvc -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  $([char]0x2022) Accounts Missing AES Keys (pwd >5yr): $($assessment.TotalMissingAES)" -ForegroundColor $(if ($assessment.TotalMissingAES -gt 0) { "Yellow" } else { "Green" })
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -match "Failed to contact Domain Controller '([^']+)'") {
            Write-Finding -Status "CRITICAL" -Message $errorMsg
        }
        elseif ($ServerParams.ContainsKey('Server')) {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing accounts (Attempted DC: $($ServerParams['Server'])): $errorMsg"
        }
        else {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing accounts: $errorMsg"
        }
    }
    
    return $assessment
}

function Show-AssessmentSummary {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Results
    )
    
    Write-Section "Assessment Summary Tables"
    
    # 1. Domain Controller Summary Table
    Write-Host "`n  DOMAIN CONTROLLER SUMMARY" -ForegroundColor Cyan
    Write-Host ("  " + ([string]([char]0x2500) * 100)) -ForegroundColor DarkGray
    
    if ($Results.DomainControllers.Details.Count -gt 0) {
        $dcTable = @()
        
        foreach ($dc in $Results.DomainControllers.Details) {
            # Determine status color
            $status = "OK"
            if ($dc.EncryptionTypes -match "DES") {
                $status = "CRITICAL"
            }
            elseif ($dc.EncryptionTypes -match "RC4") {
                $status = "WARNING"
            }
            
            # Check GPO status
            $gpoStatus = if ($Results.DomainControllers.GPOConfigured) { 
                if ($Results.DomainControllers.GPOEncryptionTypes -match "DES") { "CRITICAL" }
                elseif ($Results.DomainControllers.GPOEncryptionTypes -match "RC4") { "WARNING" }
                else { "OK" }
            }
            else { "Not Configured" }
            
            $dcTable += [PSCustomObject]@{
                'Domain Controller' = $dc.Name
                'Status'            = $status
                'Encryption Types'  = $dc.EncryptionTypes
                'Attribute Value'   = if ($dc.EncryptionValue) { "0x$($dc.EncryptionValue.ToString('X'))" } else { "Not Set" }
                'GPO Status'        = $gpoStatus
                'Operating System'  = $dc.OperatingSystem
            }
        }
        
        # Display table with color coding
        $dcTable | Format-Table -AutoSize | Out-String -Stream | ForEach-Object {
            if ($_ -match "CRITICAL") {
                Write-Host "  $_" -ForegroundColor Red
            }
            elseif ($_ -match "WARNING") {
                Write-Host "  $_" -ForegroundColor Yellow
            }
            elseif ($_ -match "OK") {
                Write-Host "  $_" -ForegroundColor Green
            }
            elseif ($_ -match "Domain Controller|^-+$") {
                Write-Host "  $_" -ForegroundColor Cyan
            }
            else {
                Write-Host "  $_"
            }
        }
        
        # Summary statistics
        Write-Host "`n  Summary:" -ForegroundColor Cyan
        Write-Host "    Total DCs: $($Results.DomainControllers.TotalDCs)" -ForegroundColor White
        if ($Results.DomainControllers.DESConfigured -gt 0) {
            Write-Host "    DES Configured: $($Results.DomainControllers.DESConfigured)" -ForegroundColor Red
        }
        if ($Results.DomainControllers.RC4Configured -gt 0) {
            Write-Host "    RC4 Configured: $($Results.DomainControllers.RC4Configured)" -ForegroundColor Yellow
        }
        if ($Results.DomainControllers.AESConfigured -gt 0) {
            Write-Host "    AES Configured: $($Results.DomainControllers.AESConfigured)" -ForegroundColor Green
        }
    }
    else {
        Write-Host "  No Domain Controller data available" -ForegroundColor Yellow
    }
    
    # 2. Event Log Summary Table
    if ($Results.EventLogs) {
        Write-Host "`n`n  EVENT LOG ANALYSIS SUMMARY" -ForegroundColor Cyan
        Write-Host ("  " + ([string]([char]0x2500) * 100)) -ForegroundColor DarkGray
        
        # Debug: Check what properties we have
        Write-Verbose "EventLogs properties: $($Results.EventLogs.Keys -join ', ')"
        Write-Verbose "QueriedDCs count: $($Results.EventLogs.QueriedDCs.Count)"
        Write-Verbose "TotalEvents: $($Results.EventLogs.EventsAnalyzed)"
        
        $eventTable = @()
        
        # Add successfully queried DCs
        if ($Results.EventLogs.QueriedDCs -and $Results.EventLogs.QueriedDCs.Count -gt 0) {
            foreach ($dcName in $Results.EventLogs.QueriedDCs) {
                $eventTable += [PSCustomObject]@{
                    'Domain Controller' = $dcName
                    'Status'            = 'Success'
                    'Events Analyzed'   = if ($Results.EventLogs.EventsAnalyzed) { $Results.EventLogs.EventsAnalyzed } else { 0 }
                    'RC4 Tickets'       = if ($Results.EventLogs.RC4Tickets) { $Results.EventLogs.RC4Tickets } else { 0 }
                    'DES Tickets'       = if ($Results.EventLogs.DESTickets) { $Results.EventLogs.DESTickets } else { 0 }
                    'Error Message'     = '-'
                }
            }
        }
        
        # Add failed DCs
        if ($Results.EventLogs.FailedDCs -and $Results.EventLogs.FailedDCs.Count -gt 0) {
            foreach ($failed in $Results.EventLogs.FailedDCs) {
                $eventTable += [PSCustomObject]@{
                    'Domain Controller' = $failed.Name
                    'Status'            = 'Failed'
                    'Events Analyzed'   = 0
                    'RC4 Tickets'       = 0
                    'DES Tickets'       = 0
                    'Error Message'     = $failed.Error
                }
            }
        }
        
        # Display table with color coding
        if ($eventTable.Count -gt 0) {
            $eventTable | Format-Table -AutoSize -Wrap | Out-String -Stream | ForEach-Object {
                if ($_ -match "Failed") {
                    Write-Host "  $_" -ForegroundColor Red
                }
                elseif ($_ -match "Success") {
                    Write-Host "  $_" -ForegroundColor Green
                }
                elseif ($_ -match "Domain Controller|^-+$") {
                    Write-Host "  $_" -ForegroundColor Cyan
                }
                else {
                    Write-Host "  $_"
                }
            }
            
            # Summary statistics
            Write-Host "`n  Summary:" -ForegroundColor Cyan
            Write-Host "    Total Events Analyzed: $($Results.EventLogs.EventsAnalyzed)" -ForegroundColor White
            if ($Results.EventLogs.RC4Tickets -gt 0) {
                Write-Host "    RC4 Tickets Detected: $($Results.EventLogs.RC4Tickets)" -ForegroundColor Red
            }
            if ($Results.EventLogs.DESTickets -gt 0) {
                Write-Host "    DES Tickets Detected: $($Results.EventLogs.DESTickets)" -ForegroundColor Red
            }
            if ($Results.EventLogs.FailedDCs.Count -gt 0) {
                Write-Host "    Failed DC Queries: $($Results.EventLogs.FailedDCs.Count)" -ForegroundColor Yellow
            }
        }
        else {
            # Event logs section exists but no data - likely DC discovery failed
            Write-Host "  Event log analysis was attempted but no data was collected" -ForegroundColor Yellow
            Write-Host "  This typically means DC discovery failed (see errors above)" -ForegroundColor Yellow
            Write-Host "  Review the 'Event Log Analysis' section for specific error details" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "`n`n  EVENT LOG ANALYSIS SUMMARY" -ForegroundColor Cyan
        Write-Host ("  " + ([string]([char]0x2500) * 100)) -ForegroundColor DarkGray
        Write-Host "  Event log analysis was not performed (use -AnalyzeEventLogs parameter)" -ForegroundColor Gray
    }
    
    # 3. Trust Summary Table (if trusts exist)
    if ($Results.Trusts -and $Results.Trusts.Details.Count -gt 0) {
        Write-Host "`n`n  TRUST ENCRYPTION SUMMARY" -ForegroundColor Cyan
        Write-Host ("  " + ([string]([char]0x2500) * 100)) -ForegroundColor DarkGray
        
        $trustTable = @()
        
        foreach ($trust in $Results.Trusts.Details) {
            # Determine risk level
            $risk = "LOW"
            if ($trust.EncryptionTypes -match "DES") {
                $risk = "CRITICAL"
            }
            elseif ($trust.EncryptionTypes -match "RC4") {
                $risk = "HIGH"
            }
            
            $trustTable += [PSCustomObject]@{
                'Trust Name'       = $trust.Name
                'Direction'        = $trust.Direction
                'Encryption Types' = $trust.EncryptionTypes
                'Risk Level'       = $risk
            }
        }
        
        # Display table with color coding
        $trustTable | Format-Table -AutoSize | Out-String -Stream | ForEach-Object {
            if ($_ -match "CRITICAL") {
                Write-Host "  $_" -ForegroundColor Red
            }
            elseif ($_ -match "HIGH") {
                Write-Host "  $_" -ForegroundColor Yellow
            }
            elseif ($_ -match "LOW") {
                Write-Host "  $_" -ForegroundColor Green
            }
            elseif ($_ -match "Trust Name|^-+$") {
                Write-Host "  $_" -ForegroundColor Cyan
            }
            else {
                Write-Host "  $_"
            }
        }
        
        # Summary statistics
        Write-Host "`n  Summary:" -ForegroundColor Cyan
        Write-Host "    Total Trusts: $($Results.Trusts.TotalTrusts)" -ForegroundColor White
        if ($Results.Trusts.DESRisk -gt 0) {
            Write-Host "    DES Risk: $($Results.Trusts.DESRisk) trust(s)" -ForegroundColor Red
        }
        if ($Results.Trusts.RC4Risk -gt 0) {
            Write-Host "    RC4 Risk: $($Results.Trusts.RC4Risk) trust(s)" -ForegroundColor Yellow
        }
        if ($Results.Trusts.AESSecure -gt 0) {
            Write-Host "    AES Secure: $($Results.Trusts.AESSecure) trust(s)" -ForegroundColor Green
        }
    }
    
    # 4. KRBTGT & Account Summary Table
    if ($Results.Accounts) {
        Write-Host "`n`n  KRBTGT & ACCOUNT ENCRYPTION SUMMARY" -ForegroundColor Cyan
        Write-Host ("  " + ([string]([char]0x2500) * 100)) -ForegroundColor DarkGray
        
        # KRBTGT row
        $krbtgtTable = @()
        $krbtgtStatus = $Results.Accounts.KRBTGT.Status
        $krbtgtTable += [PSCustomObject]@{
            'Account'          = 'krbtgt'
            'Type'             = 'KRBTGT'
            'Status'           = $krbtgtStatus
            'Password Age'     = if ($Results.Accounts.KRBTGT.PasswordAgeDays -ge 0) { "$($Results.Accounts.KRBTGT.PasswordAgeDays) days" } else { "Unknown" }
            'Encryption Types' = if ($Results.Accounts.KRBTGT.EncryptionTypes) { $Results.Accounts.KRBTGT.EncryptionTypes } else { "Not Set" }
        }
        
        # DES flag accounts
        foreach ($acct in $Results.Accounts.DESFlagAccounts) {
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $acct.Name
                'Type'             = 'USE_DES_KEY_ONLY'
                'Status'           = 'CRITICAL'
                'Password Age'     = if ($acct.PasswordLastSet) { "$([int]((Get-Date) - $acct.PasswordLastSet).TotalDays) days" } else { "Unknown" }
                'Encryption Types' = $acct.EncryptionTypes
            }
        }
        
        # RC4/DES-only service accounts
        foreach ($svc in $Results.Accounts.RC4OnlyServiceAccounts) {
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $svc.Name
                'Type'             = $svc.Type
                'Status'           = 'CRITICAL'
                'Password Age'     = if ($svc.PasswordAgeDays -ge 0) { "$($svc.PasswordAgeDays) days" } else { "Unknown" }
                'Encryption Types' = $svc.EncryptionTypes
            }
        }
        
        # Stale password service accounts (not already in RC4-only list)
        foreach ($svc in $Results.Accounts.StaleServiceAccounts) {
            if ($svc.Name -notin $Results.Accounts.RC4OnlyServiceAccounts.Name) {
                $krbtgtTable += [PSCustomObject]@{
                    'Account'          = $svc.Name
                    'Type'             = 'Stale Password SPN'
                    'Status'           = 'WARNING'
                    'Password Age'     = "$($svc.PasswordAgeDays) days"
                    'Encryption Types' = $svc.EncryptionTypes
                }
            }
        }
        
        # RC4-only MSAs
        foreach ($msa in $Results.Accounts.RC4OnlyMSAs) {
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $msa.Name
                'Type'             = "RC4-Only $($msa.Type)"
                'Status'           = 'WARNING'
                'Password Age'     = if ($msa.PasswordLastSet) { "$([int]((Get-Date) - $msa.PasswordLastSet).TotalDays) days" } else { "Auto-managed" }
                'Encryption Types' = $msa.EncryptionTypes
            }
        }
        
        # Display table with color coding
        $krbtgtTable | Format-Table -AutoSize | Out-String -Stream | ForEach-Object {
            if ($_ -match "CRITICAL") {
                Write-Host "  $_" -ForegroundColor Red
            }
            elseif ($_ -match "WARNING") {
                Write-Host "  $_" -ForegroundColor Yellow
            }
            elseif ($_ -match "^.*OK.*$" -and $_ -notmatch "Account|^-+$") {
                Write-Host "  $_" -ForegroundColor Green
            }
            elseif ($_ -match "Account|^-+$") {
                Write-Host "  $_" -ForegroundColor Cyan
            }
            else {
                Write-Host "  $_"
            }
        }
        
        # Summary statistics
        Write-Host "`n  Summary:" -ForegroundColor Cyan
        Write-Host "    KRBTGT Status: $($Results.Accounts.KRBTGT.Status)" -ForegroundColor $(
            switch ($Results.Accounts.KRBTGT.Status) { "OK" { "Green" } "WARNING" { "Yellow" } "CRITICAL" { "Red" } default { "Gray" } }
        )
        if ($Results.Accounts.TotalDESFlag -gt 0) {
            Write-Host "    USE_DES_KEY_ONLY Accounts: $($Results.Accounts.TotalDESFlag)" -ForegroundColor Red
        }
        if ($Results.Accounts.TotalRC4OnlySvc -gt 0) {
            Write-Host "    RC4/DES-Only Service Accounts: $($Results.Accounts.TotalRC4OnlySvc)" -ForegroundColor Red
        }
        if ($Results.Accounts.TotalRC4OnlyMSA -gt 0) {
            Write-Host "    RC4-Only MSAs: $($Results.Accounts.TotalRC4OnlyMSA)" -ForegroundColor Yellow
        }
        if ($Results.Accounts.TotalStaleSvc -gt 0) {
            Write-Host "    Stale Password Service Accounts: $($Results.Accounts.TotalStaleSvc)" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
}

function Show-ManualValidationGuidance {
    Write-Section "Manual Validation & Monitoring Guidance"
    
    Write-Host @"

$([System.Char]::ConvertFromUtf32(0x1F4CB)) RECOMMENDED MANUAL VALIDATION STEPS:

1. Event Log Monitoring Setup
   $([string]([char]0x2500) * 60)
   Enable advanced Kerberos auditing on Domain Controllers:
   
   $([char]0x2022) Group Policy > Computer Configuration > Policies > Windows Settings
     > Security Settings > Advanced Audit Policy Configuration
     > Audit Policies > Account Logon
   
   $([char]0x2713) Audit Kerberos Authentication Service: Success and Failure
   $([char]0x2713) Audit Kerberos Service Ticket Operations: Success and Failure
   
   Event IDs to monitor:
   $([char]0x2022) 4768: TGT Request (TicketEncryptionType field)
   $([char]0x2022) 4769: Service Ticket Request (TicketEncryptionType field)
   
   Encryption Type Values:
   $([char]0x2022) 0x1 or 0x3: DES (CRITICAL - should be 0)
   $([char]0x2022) 0x17: RC4-HMAC (WARNING - should be 0)
   $([char]0x2022) 0x11 or 0x12: AES (GOOD - expected value)

2. Splunk/SIEM Query Examples
   $([string]([char]0x2500) * 60)
   
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
   $([string]([char]0x2500) * 60)
   
   Verify GPO is applied and effective:
   
   On a Domain Controller:
   PS> gpresult /h C:\gpresult.html
   PS> Start-Process C:\gpresult.html
   
   Look for: "Network security: Configure encryption types allowed for Kerberos"
   Should show: AES128_HMAC_SHA1, AES256_HMAC_SHA1
   Should NOT show: DES_CBC_CRC, DES_CBC_MD5, RC4_HMAC_MD5

4. Computer Object Assessment (If Needed)
   $([string]([char]0x2500) * 60)
   
   Post-November 2022 Update Clarification:
   
   RC4 fallback ONLY occurs when BOTH conditions are true:
   a) msDS-SupportedEncryptionTypes on CLIENT is set to non-zero value
   b) msDS-SupportedEncryptionTypes on DC does NOT include AES
   
   If your DCs have AES configured via GPO, client computers will inherit AES
   even if their msDS-SupportedEncryptionTypes attribute is not populated.
   
   You do NOT need to populate this attribute on all 100,000+ computers if:
   $([char]0x2713) DCs have AES configured (via GPO or attribute)
   $([char]0x2713) Event logs show no RC4 usage (0x17)
   
   To verify a specific computer:
   PS> Get-ADComputer "COMPUTERNAME" -Properties msDS-SupportedEncryptionTypes
   
   Value of 0 or empty: Inherits from DC (normal and secure post-Nov 2022)
   Value with 0x4 bit: Has RC4 explicitly set (investigate why)

5. Trust Validation
   $([string]([char]0x2500) * 60)
   
   Post-November 2022: Trusts default to AES when attribute is not set.
   
   To verify trust encryption from both sides:
   PS> Get-ADTrust -Filter * | Select-Object Name, msDS-SupportedEncryptionTypes
   
   If msDS-SupportedEncryptionTypes is 0 or empty: Uses AES (secure)
   If set to 0x18 or 0x1C: Explicitly configured for AES (secure)
   If includes 0x4: RC4 enabled (investigate)

6. KRBTGT Account & Service Account Hygiene
   $([string]([char]0x2500) * 60)
   
   KRBTGT Password Rotation:
   $([char]0x2022) The KRBTGT password encrypts all TGTs in the domain
   $([char]0x2022) If never rotated since pre-AES era, only RC4/DES keys may exist
   $([char]0x2022) Microsoft recommends rotation at least every 180 days
   $([char]0x2022) AD retains the CURRENT and PREVIOUS KRBTGT password (N and N-1)
   $([char]0x2022) Rotate TWICE to flush out old keys entirely

   $([char]0x26A0) KRBTGT Rotation Step-by-Step Procedure:
   
   a) Pre-Rotation Checks:
      $([char]0x2022) Confirm ALL Domain Controllers are online and replicating
        PS> repadmin /replsummary
        PS> Get-ADDomainController -Filter * | ForEach-Object {
              Test-Connection `$_.HostName -Count 1 -Quiet }
      $([char]0x2022) Note the current password age:
        PS> Get-ADUser krbtgt -Properties PasswordLastSet |
            Select-Object Name, PasswordLastSet

   b) First Rotation:
      PS> # Reset the KRBTGT password (generates new AES/RC4 keys)
      PS> Reset-ADAccountPassword -Identity krbtgt -NewPassword `
            (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force) -Reset
      $([char]0x2022) Alternative using AD Users & Computers:
        Right-click krbtgt > Reset Password > enter random complex password
      $([char]0x2022) After reset, AD still accepts tickets encrypted with the
        PREVIOUS password (N-1), so existing TGTs remain valid.

   c) Wait for Replication:
      $([char]0x2022) Wait at LEAST 10-12 hours (or 2x the maximum TGT lifetime,
        which defaults to 10 hours) so all outstanding TGTs expire.
      $([char]0x2022) Verify the password change has replicated to ALL DCs:
        PS> Get-ADDomainController -Filter * | ForEach-Object {
              Get-ADUser krbtgt -Server `$_.HostName -Properties PasswordLastSet |
              Select-Object @{N='DC';E={`$_.DistinguishedName.Split(',')[1]}},
                            PasswordLastSet }
      $([char]0x2022) Monitor for Kerberos errors (Event IDs 4768/4769 failures,
        Event ID 4771 with failure code 0x18 = bad password).
      $([char]0x2022) If you see widespread authentication failures, do NOT
        proceed with the second rotation; investigate first.

   d) Second Rotation:
      PS> # Second reset flushes out the old N-1 password entirely
      PS> Reset-ADAccountPassword -Identity krbtgt -NewPassword `
            (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force) -Reset
      $([char]0x2022) After this, only the two newest passwords are valid.
        Any tickets from the original (pre-rotation) key are now invalid.
      $([char]0x2022) Wait for replication again and monitor for errors.

   e) Post-Rotation Validation:
      PS> # Verify the new password date
      PS> Get-ADUser krbtgt -Properties PasswordLastSet, `
            'msDS-SupportedEncryptionTypes' |
            Select-Object Name, PasswordLastSet, msDS-SupportedEncryptionTypes
      PS> # Confirm no authentication errors in event logs
      PS> Get-WinEvent -FilterHashtable @{LogName='Security';Id=4771;
            StartTime=(Get-Date).AddHours(-2)} -ErrorAction SilentlyContinue |
            Where-Object { `$_.Message -match 'krbtgt' }

   $([char]0x26A0) Important Caveats:
   $([char]0x2022) NEVER rotate KRBTGT more than twice in quick succession
   $([char]0x2022) Golden Ticket attacks are invalidated by a double rotation
   $([char]0x2022) Azure AD Connect / Entra Connect: rotation is safe as it
     does not use Kerberos TGTs for cloud sync
   $([char]0x2022) Read-Only DCs (RODCs) have their own krbtgt_XXXXX accounts;
     these are rotated independently if needed
   $([char]0x2022) Consider using Microsoft's official KRBTGT reset script:
     https://github.com/microsoft/New-KrbtgtKeys.ps1

   Check KRBTGT:
   PS> Get-ADUser krbtgt -Properties PasswordLastSet, msDS-SupportedEncryptionTypes |
       Select-Object Name, PasswordLastSet, msDS-SupportedEncryptionTypes
   
   Service Accounts with RC4/DES:
   PS> Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties `
       msDS-SupportedEncryptionTypes, PasswordLastSet, ServicePrincipalName |
       Where-Object { `$_.'msDS-SupportedEncryptionTypes' -band 4 -and
                       -not (`$_.'msDS-SupportedEncryptionTypes' -band 0x18) } |
       Select-Object Name, PasswordLastSet, msDS-SupportedEncryptionTypes
   
   Remove USE_DES_KEY_ONLY flag:
   PS> Get-ADUser -Filter 'UserAccountControl -band 2097152' |
       ForEach-Object { Set-ADAccountControl `$_ -UseDESKeyOnly `$false }
   
   Update service accounts to AES:
   PS> Set-ADUser "ServiceAccount" -Replace @{'msDS-SupportedEncryptionTypes'=24}
   # Then reset the password to generate new AES keys
   # IMPORTANT: After changing encryption types, purge cached tickets:
   # CMD> klist purge
   # Then test access to the application

7. RC4 Disablement Timeline & Registry Keys
   $([string]([char]0x2500) * 60)
   
   $([char]0x26A0) CRITICAL TIMELINE:
   $([char]0x2022) January 2026: Security updates add RC4DefaultDisablementPhase
     registry key. Set to 1 on all DCs to begin RC4 disablement.
   $([char]0x2022) July 2026: RC4 completely removed from Kerberos KDC path,
     EXCEPT for accounts with explicit RC4 in msDS-SupportedEncryptionTypes.
   
   Registry Keys to Configure:
   $([char]0x2022) HKLM\SYSTEM\CurrentControlSet\Services\Kdc
   
   a) RC4DefaultDisablementPhase (DWORD):
      $([char]0x2022) Value = 1: Disables RC4 for accounts without explicit RC4
      $([char]0x2022) Deploy to ALL Domain Controllers after January 2026 updates
      PS> Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
            -Name 'RC4DefaultDisablementPhase' -Value 1 -Type DWord
   
   b) DefaultDomainSupportedEncTypes (DWORD):
      $([char]0x2022) Controls default encryption types for the domain
      $([char]0x2022) If set, MUST include RC4 (0x4) if you need explicit RC4
        exceptions post-July 2026
      $([char]0x2022) Usually NOT set (uses OS defaults) - verify before changing
      PS> # Check current value:
      PS> Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
            -Name 'DefaultDomainSupportedEncTypes' -ErrorAction SilentlyContinue
   
   $([char]0x2022) GPO Preference path for DefaultDomainSupportedEncTypes:
     Computer Configuration > Preferences > Windows Settings > Registry
     > DefaultDomainSupportedEncTypes

8. Explicit RC4 Exception Workflow (Post-July 2026)
   $([string]([char]0x2500) * 60)
   
   After July 2026, RC4 is blocked UNLESS explicitly configured on the account's
   msDS-SupportedEncryptionTypes attribute. Use this workflow:
   
   a) Step 1: Try AES First
      PS> # Set account to AES-only
      PS> Set-ADUser "svc_LegacyApp" -Replace @{'msDS-SupportedEncryptionTypes'=24}
      PS> # Reset password to generate AES keys
      PS> Set-ADAccountPassword "svc_LegacyApp" -Reset
      CMD> klist purge
      $([char]0x2022) Test application access
   
   b) Step 2: If AES Fails, Add Explicit RC4 Exception
      For USER/SERVICE accounts:
      PS> Set-ADUser "svc_LegacyApp" -Replace @{'msDS-SupportedEncryptionTypes'=0x1C}
      # 0x1C = RC4 (0x4) + AES128 (0x8) + AES256 (0x10)
      PS> Set-ADAccountPassword "svc_LegacyApp" -Reset
      CMD> klist purge
      $([char]0x2022) Test application access
   
      For COMPUTER accounts (rare but possible):
      PS> Set-ADComputer "LEGACYHOST" -Replace @{'msDS-SupportedEncryptionTypes'=0x1C}
      CMD> klist purge
      $([char]0x2022) Test application access
   
   c) Step 3: Document and Plan
      $([char]0x2022) Document all accounts with explicit RC4 exceptions
      $([char]0x2022) Engage vendors for AES support on third-party systems
      $([char]0x2022) Plan upgrades or replacements for legacy systems
      $([char]0x2022) Set review dates to revisit each exception
   
   $([char]0x26A0) Ensure DefaultDomainSupportedEncTypes on DCs still
   includes RC4 (0x4) if you have any explicit RC4 exceptions.

9. Accounts Missing AES Keys
   $([string]([char]0x2500) * 60)
   
   Accounts whose password was last set BEFORE the Domain Functional Level
   was raised to Windows Server 2008 will NOT have AES keys generated.
   
   To remediate:
   $([char]0x2022) Reset password TWICE (use different or same password)
   $([char]0x2022) Update services running under these accounts with new password
   $([char]0x2022) After reset, AES keys are automatically generated
   
   Find affected accounts:
   PS> Get-ADUser -Filter 'Enabled -eq `$true' -Properties PasswordLastSet, `
       'msDS-SupportedEncryptionTypes' |
       Where-Object { `$_.PasswordLastSet -lt (Get-Date).AddYears(-5) -and
                       (-not `$_.'msDS-SupportedEncryptionTypes' -or
                        `$_.'msDS-SupportedEncryptionTypes' -eq 0) } |
       Select-Object Name, PasswordLastSet
   
   $([char]0x26A0) For service accounts, coordinate password reset with
   application teams to avoid service disruptions.

10. Microsoft Kerberos-Crypto Tools
   $([string]([char]0x2500) * 60)
   
   Microsoft provides complementary scripts for RC4 detection:
   $([char]0x2022) Get-KerbEncryptionUsage.ps1 - Detects RC4 usage from events 4768/4769
   $([char]0x2022) List-AccountKeys.ps1 - Lists account encryption key types
   
   Download from: https://github.com/microsoft/Kerberos-Crypto
   
   More info: https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-rc4

11. Recommended Monitoring Schedule
   $([string]([char]0x2500) * 60)
   
   $([char]0x2022) Weekly: Check for RC4/DES events (automated alert)
   $([char]0x2022) Monthly: Review this assessment
   $([char]0x2022) Quarterly: Full security audit including Kerberos encryption
   $([char]0x2022) Before major changes: Re-run assessment

"@ -ForegroundColor White

    Write-Host "`n$([System.Char]::ConvertFromUtf32(0x1F4DA)) Reference Documentation:" -ForegroundColor Cyan
    Write-Host "  $([char]0x2022) KB5021131: Managing Kerberos protocol changes post-November 2022" -ForegroundColor Gray
    Write-Host "  $([char]0x2022) https://techcommunity.microsoft.com/blog/askds/what-happened-to-kerberos-authentication-after-installing-the-november-2022oob-u/3696351" -ForegroundColor Gray
    Write-Host "  $([char]0x2022) https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797" -ForegroundColor Gray
    Write-Host "  $([char]0x2022) https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-rc4" -ForegroundColor Gray
    Write-Host "  $([char]0x2022) https://github.com/microsoft/Kerberos-Crypto" -ForegroundColor Gray
}

#endregion

#region Main Execution

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
    $results.Accounts = Get-AccountEncryptionAssessment -ServerParams $serverParams
    
    # 4. KDC Registry Assessment
    $results.KdcRegistry = Get-KdcRegistryAssessment -ServerParams $serverParams
    
    # 5. Event Log Analysis (if requested)
    if ($AnalyzeEventLogs) {
        # 5a. Check audit policy first
        $results.AuditPolicy = Get-AuditPolicyCheck -ServerParams $serverParams
        
        # 5b. Analyze event logs
        $results.EventLogs = Get-EventLogEncryptionAnalysis -ServerParams $serverParams -Hours $EventLogHours
    }
    elseif (-not $QuickScan) {
        Write-Section "Event Log Analysis" -Color "Yellow"
        Write-Finding -Status "INFO" -Message "Event log analysis skipped. Use -AnalyzeEventLogs to enable."
        Write-Host "  This provides real-world usage data showing actual DES/RC4 tickets." -ForegroundColor Gray
        Write-Host "  Example: .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 48" -ForegroundColor Gray
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
                "# Or configure via GPO: 'Network security: Configure encryption types allowed for Kerberos' = AES128 + AES256"
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
                "# If AES fails, add explicit RC4 exception: -Replace @{'msDS-SupportedEncryptionTypes'=0x1C}"
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
            $missingNames = ($results.Accounts.MissingAESKeyAccounts | Select-Object -First 5).Name -join ', '
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] $($results.Accounts.TotalMissingAES) account(s) may be missing AES keys: $missingNames"
                Fix     = @(
                    "# Reset password TWICE to generate AES keys (use different or same password):"
                    "Set-ADAccountPassword '<AccountName>' -Reset"
                    "# Wait a few minutes, then reset again. Update services with new password."
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
                    "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'DefaultDomainSupportedEncTypes' -Value 28 -Type DWord"
                    "# 28 = 0x1C = RC4 + AES128 + AES256 (keep RC4 for explicit exceptions)"
                )
            }
        }
        if ($results.KdcRegistry.RC4DefaultDisablementPhase.Status -in @("NOT SET", "WARNING")) {
            $warnings++
            $phaseMsg = if ($results.KdcRegistry.RC4DefaultDisablementPhase.Status -eq "NOT SET") {
                "RC4DefaultDisablementPhase not set"
            }
            else {
                "RC4DefaultDisablementPhase = 0 (not active)"
            }
            $results.Recommendations += @{
                Level   = "WARNING"
                Message = "[$($results.Domain)] $phaseMsg"
                Fix     = @(
                    "# Deploy January 2026+ security updates, then on each DC:"
                    "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'RC4DefaultDisablementPhase' -Value 1 -Type DWord"
                    "# This disables RC4 for accounts without explicit RC4 in msDS-SupportedEncryptionTypes"
                )
            }
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
        $exportFolder = Join-Path -Path $PSScriptRoot -ChildPath "Exports"
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
                Type            = "Domain Controller"
                Name            = $dc.Name
                Status          = $dc.Status
                EncryptionTypes = $dc.EncryptionTypes
                EncryptionValue = $dc.EncryptionValue
            }
        }
        
        # Add trust details
        foreach ($trust in $results.Trusts.Details) {
            $csvData += [PSCustomObject]@{
                Type            = "Trust"
                Name            = $trust.Name
                Status          = $trust.Status
                EncryptionTypes = $trust.EncryptionTypes
                EncryptionValue = $trust.EncryptionValue
            }
        }
        
        # Add KRBTGT details
        if ($results.Accounts) {
            $csvData += [PSCustomObject]@{
                Type            = "KRBTGT"
                Name            = "krbtgt"
                Status          = "$($results.Accounts.KRBTGT.Status) (Password age: $($results.Accounts.KRBTGT.PasswordAgeDays) days)"
                EncryptionTypes = $results.Accounts.KRBTGT.EncryptionTypes
                EncryptionValue = $results.Accounts.KRBTGT.EncryptionValue
            }
            
            # Add DES flag accounts
            foreach ($acct in $results.Accounts.DESFlagAccounts) {
                $csvData += [PSCustomObject]@{
                    Type            = "DES Flag Account"
                    Name            = $acct.Name
                    Status          = "USE_DES_KEY_ONLY"
                    EncryptionTypes = $acct.EncryptionTypes
                    EncryptionValue = $acct.EncryptionValue
                }
            }
            
            # Add RC4/DES-only service accounts
            foreach ($svc in $results.Accounts.RC4OnlyServiceAccounts) {
                $csvData += [PSCustomObject]@{
                    Type            = $svc.Type
                    Name            = $svc.Name
                    Status          = "$($svc.Type) (Password age: $($svc.PasswordAgeDays) days)"
                    EncryptionTypes = $svc.EncryptionTypes
                    EncryptionValue = $svc.EncryptionValue
                }
            }
            
            # Add RC4-only MSAs
            foreach ($msa in $results.Accounts.RC4OnlyMSAs) {
                $csvData += [PSCustomObject]@{
                    Type            = "RC4-Only $($msa.Type)"
                    Name            = $msa.Name
                    Status          = "RC4-Only"
                    EncryptionTypes = $msa.EncryptionTypes
                    EncryptionValue = $msa.EncryptionValue
                }
            }
            
            # Add accounts missing AES keys
            foreach ($acct in $results.Accounts.MissingAESKeyAccounts) {
                $csvData += [PSCustomObject]@{
                    Type            = "Missing AES Keys"
                    Name            = $acct.Name
                    Status          = "Password age: $($acct.PasswordAgeDays) days"
                    EncryptionTypes = "Not Set"
                    EncryptionValue = $null
                }
            }
        }
        
        # Add KDC registry data
        if ($results.KdcRegistry) {
            $csvData += [PSCustomObject]@{
                Type            = "KDC Registry"
                Name            = "DefaultDomainSupportedEncTypes"
                Status          = $results.KdcRegistry.DefaultDomainSupportedEncTypes.Status
                EncryptionTypes = if ($results.KdcRegistry.DefaultDomainSupportedEncTypes.Types) { $results.KdcRegistry.DefaultDomainSupportedEncTypes.Types } else { "Not Set" }
                EncryptionValue = $results.KdcRegistry.DefaultDomainSupportedEncTypes.Value
            }
            $csvData += [PSCustomObject]@{
                Type            = "KDC Registry"
                Name            = "RC4DefaultDisablementPhase"
                Status          = $results.KdcRegistry.RC4DefaultDisablementPhase.Status
                EncryptionTypes = "N/A"
                EncryptionValue = $results.KdcRegistry.RC4DefaultDisablementPhase.Value
            }
        }
        
        $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Finding -Status "OK" -Message "CSV export: $csvPath"
    }
    
    # Final summary
    Write-Header "Assessment Complete" -Color "Cyan"
    
    Write-Host "`n$([System.Char]::ConvertFromUtf32(0x1F4CA)) Summary:" -ForegroundColor Cyan
    Write-Host "  $([char]0x2022) Domain: $($results.Domain)" -ForegroundColor White
    Write-Host "  $([char]0x2022) Assessment Date: $($results.AssessmentDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
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








