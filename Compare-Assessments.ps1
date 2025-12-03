<#
.SYNOPSIS
  Compare two RC4/DES assessment results to track changes over time.

.DESCRIPTION
  This script compares two exported JSON assessment files to identify changes in:
  - Domain Controller encryption configuration
  - Trust encryption settings
  - Event log ticket usage patterns
  - Overall security posture

.NOTES
  Author: Jan Tiedemann
  Version: 2.1.0

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
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$BaselineFile,
    
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
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
        return @{Symbol = "$([char]0x2193)"; Color = "Green"; Status = "Improved"}  # ↓
    }
    elseif ($New -gt $Old) {
        return @{Symbol = "$([char]0x2191)"; Color = "Red"; Status = "Worsened"}  # ↑
    }
    else {
        return @{Symbol = "$([char]0x2192)"; Color = "Gray"; Status = "Unchanged"}  # →
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
        } else {
            Write-Host "  $([char]0x26A0) Status DEGRADED!" -ForegroundColor Red
        }
    }
    
    # Domain Controller Comparison
    Write-ComparisonSection "Domain Controller Changes"
    
    $dcChanges = @{
        TotalDCs = Get-ChangeIndicator -Old $baseline.DomainControllers.TotalDCs -New $current.DomainControllers.TotalDCs
        AESConfigured = Get-ChangeIndicator -Old $baseline.DomainControllers.AESConfigured -New $current.DomainControllers.AESConfigured
        RC4Configured = Get-ChangeIndicator -Old $baseline.DomainControllers.RC4Configured -New $current.DomainControllers.RC4Configured
        DESConfigured = Get-ChangeIndicator -Old $baseline.DomainControllers.DESConfigured -New $current.DomainControllers.DESConfigured
    }
    
    Write-Host "  Total DCs:       $($baseline.DomainControllers.TotalDCs) $($dcChanges.TotalDCs.Symbol) $($current.DomainControllers.TotalDCs)" -ForegroundColor $dcChanges.TotalDCs.Color
    Write-Host "  AES Configured:  $($baseline.DomainControllers.AESConfigured) $($dcChanges.AESConfigured.Symbol) $($current.DomainControllers.AESConfigured)" -ForegroundColor $(if ($dcChanges.AESConfigured.Status -eq "Improved") { "Green" } else { $dcChanges.AESConfigured.Color })
    Write-Host "  RC4 Configured:  $($baseline.DomainControllers.RC4Configured) $($dcChanges.RC4Configured.Symbol) $($current.DomainControllers.RC4Configured)" -ForegroundColor $(if ($dcChanges.RC4Configured.Status -eq "Improved") { "Green" } else { $dcChanges.RC4Configured.Color })
    Write-Host "  DES Configured:  $($baseline.DomainControllers.DESConfigured) $($dcChanges.DESConfigured.Symbol) $($current.DomainControllers.DESConfigured)" -ForegroundColor $(if ($dcChanges.DESConfigured.Status -eq "Improved") { "Green" } else { $dcChanges.DESConfigured.Color })
    
    # Trust Comparison
    Write-ComparisonSection "Trust Changes"
    
    $trustChanges = @{
        TotalTrusts = Get-ChangeIndicator -Old $baseline.Trusts.TotalTrusts -New $current.Trusts.TotalTrusts
        RC4Risk = Get-ChangeIndicator -Old $baseline.Trusts.RC4Risk -New $current.Trusts.RC4Risk
        DESRisk = Get-ChangeIndicator -Old $baseline.Trusts.DESRisk -New $current.Trusts.DESRisk
    }
    
    Write-Host "  Total Trusts:    $($baseline.Trusts.TotalTrusts) $($trustChanges.TotalTrusts.Symbol) $($current.Trusts.TotalTrusts)" -ForegroundColor $trustChanges.TotalTrusts.Color
    Write-Host "  RC4 Risk:        $($baseline.Trusts.RC4Risk) $($trustChanges.RC4Risk.Symbol) $($current.Trusts.RC4Risk)" -ForegroundColor $(if ($trustChanges.RC4Risk.Status -eq "Improved") { "Green" } else { $trustChanges.RC4Risk.Color })
    Write-Host "  DES Risk:        $($baseline.Trusts.DESRisk) $($trustChanges.DESRisk.Symbol) $($current.Trusts.DESRisk)" -ForegroundColor $(if ($trustChanges.DESRisk.Status -eq "Improved") { "Green" } else { $trustChanges.DESRisk.Color })
    
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
    
    $improvements = 0
    $degradations = 0
    
    # Count improvements/degradations
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
