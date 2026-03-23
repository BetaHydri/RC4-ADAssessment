<#
.SYNOPSIS
  Compare two RC4/DES assessment results to track changes over time.

.DESCRIPTION
  This script compares two exported JSON assessment files to identify changes in:
  - Domain Controller encryption configuration
  - Trust encryption settings
  - KDC registry configuration (DefaultDomainSupportedEncTypes, RC4DefaultDisablementPhase)
  - KDCSVC System events (CVE-2026-20833, events 201-209)
  - Account encryption status (KRBTGT, service accounts, DES flags, missing AES keys)
  - Event log ticket usage patterns
  - Overall security posture

.NOTES
  Author: Jan Tiedemann
  Version: 2.5.0

.PARAMETER BaselineFile
  Path to the baseline (older) assessment JSON file.

.PARAMETER CurrentFile
  Path to the current (newer) assessment JSON file.

.PARAMETER ShowDetails
  Show detailed changes for each DC and trust.

.EXAMPLE
  .\Compare-Assessments.ps1 -BaselineFile .\DES_RC4_Assessment_contoso_com_20251101_120000.json -CurrentFile .\DES_RC4_Assessment_contoso_com_20251127_150000.json

.EXAMPLE
  .\Compare-Assessments.ps1 -BaselineFile baseline.json -CurrentFile current.json -ShowDetails
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$BaselineFile,
    
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CurrentFile,
    
    [switch]$ShowDetails
)

function Write-ComparisonHeader {
    param([string]$Title)
    Write-Host "`n$(("=" * 80))" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host $(("=" * 80)) -ForegroundColor Cyan
}

function Write-ComparisonSection {
    param([string]$Title)
    Write-Host "`n$Title" -ForegroundColor Yellow
    Write-Host $(("-" * 60)) -ForegroundColor Yellow
}

function Get-ChangeIndicator {
    param([int]$Old, [int]$New)
    
    if ($New -lt $Old) {
        return @{Symbol = "$([char]0x2193)"; Color = "Green"; Status = "Improved" }  # ↓
    }
    elseif ($New -gt $Old) {
        return @{Symbol = "$([char]0x2191)"; Color = "Red"; Status = "Worsened" }  # ↑
    }
    else {
        return @{Symbol = "$([char]0x2192)"; Color = "Gray"; Status = "Unchanged" }  # →
    }
}

try {
    # Load assessment files
    Write-ComparisonHeader "RC4/DES Assessment Comparison"
    
    Write-Host "Loading baseline: " -NoNewline -ForegroundColor White
    Write-Host $BaselineFile -ForegroundColor Cyan
    $baseline = Get-Content $BaselineFile -Raw | ConvertFrom-Json
    
    Write-Host "Loading current:  " -NoNewline -ForegroundColor White
    Write-Host $CurrentFile -ForegroundColor Cyan
    $current = Get-Content $CurrentFile -Raw | ConvertFrom-Json
    
    # Basic Info
    Write-ComparisonSection "Assessment Information"
    Write-Host "  Domain: $($baseline.Domain)" -ForegroundColor White
    Write-Host "  Baseline Date: $($baseline.AssessmentDate)" -ForegroundColor Gray
    Write-Host "  Current Date:  $($current.AssessmentDate)" -ForegroundColor Gray
    
    # Overall Status Comparison
    Write-ComparisonSection "Overall Status Change"
    Write-Host "  Baseline: " -NoNewline -ForegroundColor White
    $baseColor = switch ($baseline.OverallStatus) {
        "OK" { "Green" }
        "WARNING" { "Yellow" }
        "CRITICAL" { "Red" }
        default { "Gray" }
    }
    Write-Host $baseline.OverallStatus -ForegroundColor $baseColor
    
    Write-Host "  Current:  " -NoNewline -ForegroundColor White
    $currColor = switch ($current.OverallStatus) {
        "OK" { "Green" }
        "WARNING" { "Yellow" }
        "CRITICAL" { "Red" }
        default { "Gray" }
    }
    Write-Host $current.OverallStatus -ForegroundColor $currColor
    
    if ($baseline.OverallStatus -ne $current.OverallStatus) {
        $improved = ($baseline.OverallStatus -eq "CRITICAL" -and $current.OverallStatus -ne "CRITICAL") -or
        ($baseline.OverallStatus -eq "WARNING" -and $current.OverallStatus -eq "OK")
        if ($improved) {
            Write-Host "  $([char]0x2713) Status IMPROVED!" -ForegroundColor Green
        }
        else {
            Write-Host "  $([char]0x26A0) Status DEGRADED!" -ForegroundColor Red
        }
    }
    
    # Domain Controller Comparison
    Write-ComparisonSection "Domain Controller Changes"
    
    $dcChanges = @{
        TotalDCs      = Get-ChangeIndicator -Old $baseline.DomainControllers.TotalDCs -New $current.DomainControllers.TotalDCs
        AESConfigured = Get-ChangeIndicator -Old $baseline.DomainControllers.AESConfigured -New $current.DomainControllers.AESConfigured
        RC4Configured = Get-ChangeIndicator -Old $baseline.DomainControllers.RC4Configured -New $current.DomainControllers.RC4Configured
        DESConfigured = Get-ChangeIndicator -Old $baseline.DomainControllers.DESConfigured -New $current.DomainControllers.DESConfigured
    }
    
    Write-Host "  Total DCs:       $($baseline.DomainControllers.TotalDCs) $($dcChanges.TotalDCs.Symbol) $($current.DomainControllers.TotalDCs)" -ForegroundColor $dcChanges.TotalDCs.Color
    Write-Host "  AES Configured:  $($baseline.DomainControllers.AESConfigured) $($dcChanges.AESConfigured.Symbol) $($current.DomainControllers.AESConfigured)" -ForegroundColor $(if ($dcChanges.AESConfigured.Status -eq "Improved") { "Green" } else { $dcChanges.AESConfigured.Color })
    Write-Host "  RC4 Configured:  $($baseline.DomainControllers.RC4Configured) $($dcChanges.RC4Configured.Symbol) $($current.DomainControllers.RC4Configured)" -ForegroundColor $(if ($dcChanges.RC4Configured.Status -eq "Improved") { "Green" } else { $dcChanges.RC4Configured.Color })
    Write-Host "  DES Configured:  $($baseline.DomainControllers.DESConfigured) $($dcChanges.DESConfigured.Symbol) $($current.DomainControllers.DESConfigured)" -ForegroundColor $(if ($dcChanges.DESConfigured.Status -eq "Improved") { "Green" } else { $dcChanges.DESConfigured.Color })
    
    # AzureADKerberos detection note
    if ($current.DomainControllers.AzureADKerberos) {
        Write-Host "  Entra Kerberos:  AzureADKerberos proxy detected (excluded from DC counts)" -ForegroundColor DarkCyan
    }
    
    # Trust Comparison
    Write-ComparisonSection "Trust Changes"
    
    $trustChanges = @{
        TotalTrusts = Get-ChangeIndicator -Old $baseline.Trusts.TotalTrusts -New $current.Trusts.TotalTrusts
        RC4Risk     = Get-ChangeIndicator -Old $baseline.Trusts.RC4Risk -New $current.Trusts.RC4Risk
        DESRisk     = Get-ChangeIndicator -Old $baseline.Trusts.DESRisk -New $current.Trusts.DESRisk
    }
    
    Write-Host "  Total Trusts:    $($baseline.Trusts.TotalTrusts) $($trustChanges.TotalTrusts.Symbol) $($current.Trusts.TotalTrusts)" -ForegroundColor $trustChanges.TotalTrusts.Color
    Write-Host "  RC4 Risk:        $($baseline.Trusts.RC4Risk) $($trustChanges.RC4Risk.Symbol) $($current.Trusts.RC4Risk)" -ForegroundColor $(if ($trustChanges.RC4Risk.Status -eq "Improved") { "Green" } else { $trustChanges.RC4Risk.Color })
    Write-Host "  DES Risk:        $($baseline.Trusts.DESRisk) $($trustChanges.DESRisk.Symbol) $($current.Trusts.DESRisk)" -ForegroundColor $(if ($trustChanges.DESRisk.Status -eq "Improved") { "Green" } else { $trustChanges.DESRisk.Color })
    
    # Initialize change counters early so all sections can contribute
    $improvements = 0
    $degradations = 0

    # Account Comparison (v2.2.0+ data)
    if ($baseline.Accounts -and $current.Accounts) {
        Write-ComparisonSection "Account Changes"
        
        # KRBTGT
        Write-Host "  KRBTGT Status:   $($baseline.Accounts.KRBTGT.Status) $([char]0x2192) $($current.Accounts.KRBTGT.Status)" -ForegroundColor $(if ($current.Accounts.KRBTGT.Status -eq 'OK') { 'Green' } elseif ($current.Accounts.KRBTGT.Status -eq 'WARNING') { 'Yellow' } else { 'Red' })
        Write-Host "  KRBTGT Pwd Age:  $($baseline.Accounts.KRBTGT.PasswordAgeDays)d $([char]0x2192) $($current.Accounts.KRBTGT.PasswordAgeDays)d" -ForegroundColor Gray
        
        $desFlagChange = Get-ChangeIndicator -Old ([int]$baseline.Accounts.TotalDESFlag) -New ([int]$current.Accounts.TotalDESFlag)
        $rc4SvcChange = Get-ChangeIndicator -Old ([int]$baseline.Accounts.TotalRC4OnlySvc) -New ([int]$current.Accounts.TotalRC4OnlySvc)
        $staleSvcChange = Get-ChangeIndicator -Old ([int]$baseline.Accounts.TotalStaleSvc) -New ([int]$current.Accounts.TotalStaleSvc)
        
        Write-Host "  DES Flag Accts:  $($baseline.Accounts.TotalDESFlag) $($desFlagChange.Symbol) $($current.Accounts.TotalDESFlag)" -ForegroundColor $(if ($desFlagChange.Status -eq "Improved") { "Green" } else { $desFlagChange.Color })
        Write-Host "  RC4-Only SvcAcc: $($baseline.Accounts.TotalRC4OnlySvc) $($rc4SvcChange.Symbol) $($current.Accounts.TotalRC4OnlySvc)" -ForegroundColor $(if ($rc4SvcChange.Status -eq "Improved") { "Green" } else { $rc4SvcChange.Color })
        Write-Host "  Stale Svc(RC4):  $($baseline.Accounts.TotalStaleSvc) $($staleSvcChange.Symbol) $($current.Accounts.TotalStaleSvc)" -ForegroundColor $(if ($staleSvcChange.Status -eq "Improved") { "Green" } else { $staleSvcChange.Color })
        
        # Missing AES keys (v2.3.0+)
        if ($null -ne $baseline.Accounts.TotalMissingAES -or $null -ne $current.Accounts.TotalMissingAES) {
            $missingAESChange = Get-ChangeIndicator -Old ([int]$baseline.Accounts.TotalMissingAES) -New ([int]$current.Accounts.TotalMissingAES)
            Write-Host "  Missing AES:     $([int]$baseline.Accounts.TotalMissingAES) $($missingAESChange.Symbol) $([int]$current.Accounts.TotalMissingAES)" -ForegroundColor $(if ($missingAESChange.Status -eq "Improved") { "Green" } else { $missingAESChange.Color })
        }
        
        # Count account improvements/degradations
        if ($desFlagChange.Status -eq "Improved") { $improvements++ }
        if ($desFlagChange.Status -eq "Worsened") { $degradations++ }
        if ($rc4SvcChange.Status -eq "Improved") { $improvements++ }
        if ($rc4SvcChange.Status -eq "Worsened") { $degradations++ }
        if ($staleSvcChange.Status -eq "Improved") { $improvements++ }
        if ($staleSvcChange.Status -eq "Worsened") { $degradations++ }
    }
    
    # KDC Registry Comparison (v2.3.0+ data)
    if ($baseline.KdcRegistry -and $current.KdcRegistry) {
        Write-ComparisonSection "KDC Registry Changes"
        
        $baseRC4Phase = if ($baseline.KdcRegistry.RC4DefaultDisablementPhase.Configured) { $baseline.KdcRegistry.RC4DefaultDisablementPhase.Value } else { "Not Set" }
        $currRC4Phase = if ($current.KdcRegistry.RC4DefaultDisablementPhase.Configured) { $current.KdcRegistry.RC4DefaultDisablementPhase.Value } else { "Not Set" }
        Write-Host "  RC4Disablement:  $baseRC4Phase $([char]0x2192) $currRC4Phase" -ForegroundColor $(if ($currRC4Phase -eq 2) { 'Green' } elseif ($currRC4Phase -eq 1) { 'Yellow' } elseif ($currRC4Phase -eq 'Not Set') { 'Yellow' } else { 'Gray' })
        
        $baseEncTypes = if ($baseline.KdcRegistry.DefaultDomainSupportedEncTypes.Configured) { $baseline.KdcRegistry.DefaultDomainSupportedEncTypes.Types } else { "Not Set" }
        $currEncTypes = if ($current.KdcRegistry.DefaultDomainSupportedEncTypes.Configured) { $current.KdcRegistry.DefaultDomainSupportedEncTypes.Types } else { "Not Set" }
        Write-Host "  DefaultEncTypes: $baseEncTypes $([char]0x2192) $currEncTypes" -ForegroundColor Gray

        # Count KDC registry improvements/degradations
        # RC4Disablement: becoming configured (value 1) is an improvement; becoming unconfigured is a degradation
        if ($baseRC4Phase -ne $currRC4Phase) {
            if ($currRC4Phase -ne 'Not Set' -and ($baseRC4Phase -eq 'Not Set' -or [int]$currRC4Phase -gt [int]$baseRC4Phase)) {
                $improvements++
            }
            elseif ($currRC4Phase -eq 'Not Set' -or ($baseRC4Phase -ne 'Not Set' -and [int]$currRC4Phase -lt [int]$baseRC4Phase)) {
                $degradations++
            }
        }
        # DefaultEncTypes: changing from Not Set to a configured value or removing weak enc types
        if ("$baseEncTypes" -ne "$currEncTypes") {
            if ($baseEncTypes -eq 'Not Set' -and $currEncTypes -ne 'Not Set') {
                $improvements++
            }
            elseif ($baseEncTypes -ne 'Not Set' -and $currEncTypes -eq 'Not Set') {
                $degradations++
            }
        }
    }
    
    # Event Log Comparison (if available)
    if ($baseline.EventLogs -and $current.EventLogs) {
        Write-ComparisonSection "Event Log Analysis Changes"
        
        $eventChanges = @{
            RC4Tickets = Get-ChangeIndicator -Old $baseline.EventLogs.RC4Tickets -New $current.EventLogs.RC4Tickets
            DESTickets = Get-ChangeIndicator -Old $baseline.EventLogs.DESTickets -New $current.EventLogs.DESTickets
            AESTickets = Get-ChangeIndicator -Old $baseline.EventLogs.AESTickets -New $current.EventLogs.AESTickets
        }
        
        Write-Host "  RC4 Tickets:     $($baseline.EventLogs.RC4Tickets) $($eventChanges.RC4Tickets.Symbol) $($current.EventLogs.RC4Tickets)" -ForegroundColor $(if ($eventChanges.RC4Tickets.Status -eq "Improved") { "Green" } else { $eventChanges.RC4Tickets.Color })
        Write-Host "  DES Tickets:     $($baseline.EventLogs.DESTickets) $($eventChanges.DESTickets.Symbol) $($current.EventLogs.DESTickets)" -ForegroundColor $(if ($eventChanges.DESTickets.Status -eq "Improved") { "Green" } else { $eventChanges.DESTickets.Color })
        Write-Host "  AES Tickets:     $($baseline.EventLogs.AESTickets) $($eventChanges.AESTickets.Symbol) $($current.EventLogs.AESTickets)" -ForegroundColor $(if ($eventChanges.AESTickets.Status -eq "Worsened") { "Red" } else { $eventChanges.AESTickets.Color })
    }
    
    # KDCSVC Event Comparison (v2.4.0+ data, CVE-2026-20833)
    if ($baseline.KdcSvcEvents -or $current.KdcSvcEvents) {
        Write-ComparisonSection "KDCSVC System Events (CVE-2026-20833)"
        
        $baseKdcEvents = if ($baseline.KdcSvcEvents) { [int]$baseline.KdcSvcEvents.TotalEvents } else { 0 }
        $currKdcEvents = if ($current.KdcSvcEvents) { [int]$current.KdcSvcEvents.TotalEvents } else { 0 }
        $kdcEventChange = Get-ChangeIndicator -Old $baseKdcEvents -New $currKdcEvents
        
        Write-Host "  KDCSVC Events:   $baseKdcEvents $($kdcEventChange.Symbol) $currKdcEvents" -ForegroundColor $(if ($kdcEventChange.Status -eq "Improved") { "Green" } else { $kdcEventChange.Color })
        
        $baseKdcStatus = if ($baseline.KdcSvcEvents) { $baseline.KdcSvcEvents.Status } else { 'N/A' }
        $currKdcStatus = if ($current.KdcSvcEvents) { $current.KdcSvcEvents.Status } else { 'N/A' }
        Write-Host "  KDCSVC Status:   $baseKdcStatus $([char]0x2192) $currKdcStatus" -ForegroundColor $(if ($currKdcStatus -eq 'OK') { 'Green' } elseif ($currKdcStatus -eq 'WARNING') { 'Yellow' } else { 'Gray' })
        
        if ($kdcEventChange.Status -eq "Improved") { $improvements++ }
        if ($kdcEventChange.Status -eq "Worsened") { $degradations++ }
    }
    
    # Detailed Changes
    if ($ShowDetails) {
        Write-ComparisonSection "Detailed DC Changes"
        
        $baselineDCs = @{}
        foreach ($dc in $baseline.DomainControllers.Details) {
            $baselineDCs[$dc.Name] = $dc
        }
        
        $currentDCs = @{}
        foreach ($dc in $current.DomainControllers.Details) {
            $currentDCs[$dc.Name] = $dc
        }
        
        # Check for new DCs
        foreach ($dcName in $currentDCs.Keys) {
            if (-not $baselineDCs.ContainsKey($dcName)) {
                Write-Host "  $([char]0x2713) NEW DC: $dcName - $($currentDCs[$dcName].Status)" -ForegroundColor Green
            }
        }
        
        # Check for removed DCs
        foreach ($dcName in $baselineDCs.Keys) {
            if (-not $currentDCs.ContainsKey($dcName)) {
                Write-Host "  $([char]0x26A0) REMOVED DC: $dcName" -ForegroundColor Yellow
            }
        }
        
        # Check for changed DCs
        foreach ($dcName in $currentDCs.Keys) {
            if ($baselineDCs.ContainsKey($dcName)) {
                $oldDC = $baselineDCs[$dcName]
                $newDC = $currentDCs[$dcName]
                
                if ($oldDC.Status -ne $newDC.Status) {
                    $improved = ($oldDC.Status -match "RC4|DES" -and $newDC.Status -eq "AES")
                    $symbol = if ($improved) { "$([char]0x2713)" } else { "$([char]0x26A0)" }
                    $color = if ($improved) { "Green" } else { "Yellow" }
                    Write-Host "  $symbol CHANGED: $dcName" -ForegroundColor $color
                    Write-Host "    Old: $($oldDC.Status)" -ForegroundColor Gray
                    Write-Host "    New: $($newDC.Status)" -ForegroundColor $color
                }
            }
        }
    }
    
    # Summary
    Write-ComparisonSection "Change Summary"
    
    # Count DC and Trust improvements/degradations
    if ($dcChanges.AESConfigured.Status -eq "Improved") { $improvements++ }
    if ($dcChanges.AESConfigured.Status -eq "Worsened") { $degradations++ }
    if ($dcChanges.RC4Configured.Status -eq "Improved") { $improvements++ }
    if ($dcChanges.RC4Configured.Status -eq "Worsened") { $degradations++ }
    if ($dcChanges.DESConfigured.Status -eq "Improved") { $improvements++ }
    if ($dcChanges.DESConfigured.Status -eq "Worsened") { $degradations++ }
    if ($trustChanges.RC4Risk.Status -eq "Improved") { $improvements++ }
    if ($trustChanges.RC4Risk.Status -eq "Worsened") { $degradations++ }
    if ($trustChanges.DESRisk.Status -eq "Improved") { $improvements++ }
    if ($trustChanges.DESRisk.Status -eq "Worsened") { $degradations++ }
    
    Write-Host "  $([char]0x2713) Improvements: $improvements" -ForegroundColor Green
    Write-Host "  $([char]0x26A0) Degradations: $degradations" -ForegroundColor $(if ($degradations -gt 0) { "Red" } else { "Gray" })
    
    if ($improvements -gt $degradations) {
        Write-Host "`n  $([System.Char]::ConvertFromUtf32(0x1F389)) Overall IMPROVEMENT in security posture!" -ForegroundColor Green
    }
    elseif ($degradations -gt $improvements) {
        Write-Host "`n  $([System.Char]::ConvertFromUtf32(0x26A0)) Overall DEGRADATION in security posture!" -ForegroundColor Red
    }
    else {
        Write-Host "`n  $([char]0x2192) No significant changes" -ForegroundColor Gray
    }
    
    Write-Host ""
}
catch {
    Write-Host "`nError comparing assessments: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    exit 1
}
