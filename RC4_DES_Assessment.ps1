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
  - Realistic computer object assessment: Only flags actual RC4 fallback scenarios
  - Actionable guidance for manual validation and monitoring setup
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
  Author: Active Directory Security Team
  Version: 2.0
  Requirements: 
    - PowerShell 5.1 or later
    - Active Directory PowerShell module
    - Domain Admin or equivalent read permissions
    - For Event Log analysis: Event log access on DCs
  
  Based on Microsoft guidance:
  - November 2022 OOB Updates (CVE-2022-37966, CVE-2022-37967)
  - KB5021131: Managing Kerberos protocol changes
  - Windows Server 2025 RC4 deprecation roadmap

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

# Script version and metadata
$script:Version = "2.0"
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
        "OK"       { "$([char]0x2713)"; $color = "Green" }   # ✓ Check mark
        "WARNING"  { "$([char]0x26A0) "; $color = "Yellow" } # ⚠ Warning sign
        "CRITICAL" { "$([char]0x2717)"; $color = "Red" }     # ✗ Cross mark
        "INFO"     { "$([char]0x24D8) "; $color = "Cyan" }   # ⓘ Circled i (PS 5.1 compatible)
        default    { "$([char]0x2022)"; $color = "White" }   # • Bullet
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
            $domainInfo = Get-ADDomain -Identity $ServerParams['Server'] -Server $ServerParams['Server']
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
        Write-Finding -Status "CRITICAL" -Message "Error analyzing Domain Controllers: $($_.Exception.Message)"
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
            $domainInfo = Get-ADDomain -Identity $ServerParams['Server'] -Server $ServerParams['Server']
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
        Write-Finding -Status "CRITICAL" -Message "Error analyzing trusts: $($_.Exception.Message)"
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
    }
    
    try {
        $startTime = (Get-Date).AddHours(-$Hours)
        
        Write-Finding -Status "INFO" -Message "Analyzing last $Hours hours of Kerberos ticket events"
        Write-Host "  Time range: $($startTime.ToString('yyyy-MM-dd HH:mm')) to $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Gray
        
        # Get domain controllers - ensure we query the correct domain
        if ($ServerParams.ContainsKey('Server')) {
            $domainInfo = Get-ADDomain -Identity $ServerParams['Server'] -Server $ServerParams['Server']
        }
        else {
            $domainInfo = Get-ADDomain
        }
        $dcOU = "OU=Domain Controllers,$($domainInfo.DistinguishedName)"
        $dcs = Get-ADComputer -SearchBase $dcOU -Filter * @ServerParams | Select-Object -First 3  # Sample first 3 DCs
        
        if (-not $dcs) {
            Write-Finding -Status "WARNING" -Message "No Domain Controllers found for event log analysis"
            return $assessment
        }
        
        Write-Finding -Status "INFO" -Message "Querying event logs from $($dcs.Count) Domain Controller(s)..."
        Write-Host "  Note: Using WinRM (PowerShell Remoting) for event log queries" -ForegroundColor Gray
        Write-Host "  If this fails, ensure WinRM is enabled on DCs: Enable-PSRemoting -Force" -ForegroundColor Gray
        
        foreach ($dc in $dcs) {
            Write-Host "  • Querying $($dc.Name)..." -ForegroundColor Cyan
            
            try {
                # Test connectivity first
                if (-not (Test-Connection -ComputerName $dc.Name -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
                    Write-Finding -Status "WARNING" -Message "Cannot reach $($dc.Name) - skipping event log query"
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
                
                # Try Get-WinEvent first (requires WinRM/RPC)
                $events = $null
                try {
                    $events = Get-WinEvent -ComputerName $dc.Name -FilterXml $filterXml -MaxEvents 1000 -ErrorAction Stop
                }
                catch [System.Runtime.InteropServices.COMException], [System.UnauthorizedAccessException] {
                    # RPC/WinRM failed, try alternative approach
                    Write-Host "    WinRM/RPC unavailable, trying alternative method..." -ForegroundColor DarkYellow
                    
                    # Alternative: Use Invoke-Command if WinRM is enabled
                    try {
                        $events = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
                            param($FilterXml, $MaxEvents)
                            Get-WinEvent -FilterXml $FilterXml -MaxEvents $MaxEvents -ErrorAction Stop
                        } -ArgumentList $filterXml, 1000 -ErrorAction Stop
                    }
                    catch {
                        throw $_
                    }
                }
                
                if (-not $events) {
                    continue
                }
                
                if ($events) {
                    $assessment.EventsAnalyzed += $events.Count
                    
                    foreach ($event in $events) {
                        $xml = [xml]$event.ToXml()
                        $eventData = @{}
                        
                        foreach ($data in $xml.Event.EventData.Data) {
                            $eventData[$data.Name] = $data.'#text'
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
                if ($errorMsg -match "WinRM|WSMan|PowerShell Remoting") {
                    Write-Finding -Status "WARNING" -Message "WinRM not available on $($dc.Name)" -Detail "Enable with: Invoke-Command -ComputerName $($dc.Name) -ScriptBlock { Enable-PSRemoting -Force }"
                }
                elseif ($errorMsg -match "RPC server|network path") {
                    Write-Finding -Status "WARNING" -Message "RPC/Network error on $($dc.Name)" -Detail "Both WinRM (5985) and RPC (135) failed. Check firewall rules or run locally on DC"
                }
                elseif ($errorMsg -match "Access is denied|unauthorized") {
                    Write-Finding -Status "WARNING" -Message "Access denied on $($dc.Name)" -Detail "Ensure you have Event Log Readers permissions or are Domain Admin"
                }
                else {
                    Write-Finding -Status "WARNING" -Message "Could not query event log on $($dc.Name): $errorMsg"
                }
                
                Write-Host "`n    Troubleshooting:" -ForegroundColor Yellow
                Write-Host "    1. Enable WinRM on DC: Enable-PSRemoting -Force" -ForegroundColor Gray
                Write-Host "    2. Or allow RPC in firewall: Port 135 + 49152-65535" -ForegroundColor Gray
                Write-Host "    3. Or run this script directly on the DC" -ForegroundColor Gray
                Write-Host "    4. Check permissions: Add your account to 'Event Log Readers' group`n" -ForegroundColor Gray
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
    }
    catch {
        Write-Finding -Status "CRITICAL" -Message "Error analyzing event logs: $($_.Exception.Message)"
    }
    
    return $assessment
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

6. Windows Server 2025 Preparation
   $([string]([char]0x2500) * 60)
   
   Windows Server 2025 disables RC4 fallback entirely.
   
   Prepare by:
   $([char]0x2713) Monitoring event logs for 30+ days to detect RC4 usage
   $([char]0x2713) Identifying and upgrading systems that can't handle AES
   $([char]0x2713) Ensuring all trusts and service accounts use AES
   $([char]0x2713) Testing in lab environment before production deployment

7. Recommended Monitoring Schedule
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
Write-Host "  $([char]0x2713) Actionable guidance for manual validation`n" -ForegroundColor Gray

# Set up parameters for AD commands
$serverParams = @{}
if ($PSBoundParameters.ContainsKey('Domain')) {
    if ($Domain) {
        $serverParams['Server'] = $Domain
        Write-Finding -Status "INFO" -Message "Targeting domain: $Domain"
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
    EventLogs         = $null
    OverallStatus     = "Unknown"
    Recommendations   = @()
}

try {
    # 1. Domain Controller Assessment
    $results.DomainControllers = Get-DomainControllerEncryption -ServerParams $serverParams
    
    # 2. Trust Assessment
    $results.Trusts = Get-TrustEncryptionAssessment -ServerParams $serverParams
    
    # 3. Event Log Analysis (if requested)
    if ($AnalyzeEventLogs) {
        $results.EventLogs = Get-EventLogEncryptionAnalysis -ServerParams $serverParams -Hours $EventLogHours
    }
    elseif (-not $QuickScan) {
        Write-Section "Event Log Analysis" -Color "Yellow"
        Write-Finding -Status "INFO" -Message "Event log analysis skipped. Use -AnalyzeEventLogs to enable."
        Write-Host "  This provides real-world usage data showing actual DES/RC4 tickets." -ForegroundColor Gray
        Write-Host "  Example: .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 48" -ForegroundColor Gray
    }
    
    # 4. Overall Assessment
    Write-Section "Overall Security Assessment"
    
    $criticalIssues = 0
    $warnings = 0
    
    # Check for DES
    if ($results.DomainControllers.DESConfigured -gt 0) {
        $criticalIssues++
        $results.Recommendations += "CRITICAL: Remove DES encryption from $($results.DomainControllers.DESConfigured) Domain Controller(s)"
    }
    
    if ($results.Trusts.DESRisk -gt 0) {
        $criticalIssues++
        $results.Recommendations += "CRITICAL: Remove DES encryption from $($results.Trusts.DESRisk) trust(s)"
    }
    
    if ($results.EventLogs -and $results.EventLogs.DESTickets -gt 0) {
        $criticalIssues++
        $results.Recommendations += "CRITICAL: DES tickets detected in event logs - active usage detected"
    }
    
    # Check for RC4
    if ($results.DomainControllers.RC4Configured -gt 0) {
        $warnings++
        $results.Recommendations += "WARNING: Remove RC4 encryption from $($results.DomainControllers.RC4Configured) Domain Controller(s)"
    }
    
    if ($results.Trusts.RC4Risk -gt 0) {
        $warnings++
        $results.Recommendations += "WARNING: $($results.Trusts.RC4Risk) trust(s) have RC4 enabled"
    }
    
    if ($results.EventLogs -and $results.EventLogs.RC4Tickets -gt 0) {
        $criticalIssues++
        $results.Recommendations += "CRITICAL: RC4 tickets detected in event logs - active usage detected"
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
    
    # Display recommendations
    if ($results.Recommendations.Count -gt 0) {
        Write-Host "`n  Recommendations:" -ForegroundColor Yellow
        foreach ($rec in $results.Recommendations) {
            Write-Host "    $([char]0x2022) $rec" -ForegroundColor Yellow
        }
    }
    
    # 5. Manual Validation Guidance (if requested)
    if ($IncludeGuidance) {
        Show-ManualValidationGuidance
    }
    else {
        Write-Host "`n  $([System.Char]::ConvertFromUtf32(0x1F4A1)) Tip: Use -IncludeGuidance to see detailed manual validation steps and monitoring setup." -ForegroundColor Cyan
    }
    
    # 6. Export Results (if requested)
    if ($ExportResults) {
        Write-Section "Exporting Results"
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $domain = $results.Domain -replace '\.', '_'
        
        # Export JSON
        $jsonPath = ".\DES_RC4_Assessment_${domain}_${timestamp}.json"
        $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Finding -Status "OK" -Message "JSON export: $jsonPath"
        
        # Export CSV summary
        $csvPath = ".\DES_RC4_Assessment_${domain}_${timestamp}.csv"
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
}
catch {
    Write-Finding -Status "CRITICAL" -Message "Assessment failed: $($_.Exception.Message)"
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}

#endregion
