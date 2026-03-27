function Invoke-ForestAssessment {
<#
.SYNOPSIS
  Assess all domains in an Active Directory forest for DES/RC4 encryption usage.
.DESCRIPTION
  Discovers all domains in the forest, runs Invoke-RC4Assessment against each domain
  (sequentially or in parallel with PS 7+), and consolidates results into a forest-wide summary.
.PARAMETER ForestName
  Name of the AD forest to assess. Defaults to the current forest.
.PARAMETER AnalyzeEventLogs
  Include event log analysis for each domain.
.PARAMETER EventLogHours
  Number of hours of event logs to analyze per domain (1-168). Default: 24.
.PARAMETER ExportResults
  Export individual domain results and forest summary to JSON/CSV files.
.PARAMETER IncludeGuidance
  Include full reference manual and export guidance text file per domain.
.PARAMETER Parallel
  Process domains in parallel (requires PowerShell 7+).
.PARAMETER MaxParallelDomains
  Maximum number of domains to process in parallel (1-10). Default: 3.
.EXAMPLE
  Invoke-ForestAssessment

.EXAMPLE
  Invoke-ForestAssessment -ForestName "contoso.com" -AnalyzeEventLogs -ExportResults
#>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ForestName,

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
        [switch]$Parallel,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaxParallelDomains = 3
    )


    #endregion

    # Script paths
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    # Assessment is now via Invoke-RC4Assessment module function

    # Verify assessment script exists
    if (-not (Test-Path $assessmentScript)) {
        Write-Error "RC4_DES_Assessment.ps1 not found in $scriptDir"
        exit 1
    }

    # Configure console encoding
    $null = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $Host.UI.RawUI.OutputEncoding = [System.Text.Encoding]::UTF8
    }
    catch {
        Write-Verbose "Console encoding could not be set: $($_.Exception.Message)"
    }

    Write-Host "`n$("=" * 80)" -ForegroundColor Cyan
    Write-Host "Active Directory Forest - DES/RC4 Assessment" -ForegroundColor Cyan
    Write-Host $("=" * 80) -ForegroundColor Cyan

    # Get forest information
    try {
        if ($ForestName) {
            Write-Host "`nTargeting forest: $ForestName" -ForegroundColor Yellow
            $forest = Get-ADForest -Identity $ForestName
        }
        else {
            $forest = Get-ADForest
            Write-Host "`nAssessing current forest: $($forest.Name)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Failed to get forest information: $($_.Exception.Message)"
        exit 1
    }

    # Display forest info
    Write-Host "`nForest Information:" -ForegroundColor Cyan
    Write-Host "  Name: $($forest.Name)" -ForegroundColor White
    Write-Host "  Root Domain: $($forest.RootDomain)" -ForegroundColor White
    Write-Host "  Domains: $($forest.Domains.Count)" -ForegroundColor White
    Write-Host "  Forest Functional Level: $($forest.ForestMode)" -ForegroundColor White

    # List all domains
    Write-Host "`nDomains to assess:" -ForegroundColor Cyan
    $domainList = $forest.Domains | Sort-Object
    foreach ($domain in $domainList) {
        Write-Host "  $([char]0x2022) $domain" -ForegroundColor Gray
    }

    Write-Host "`nAssessment Configuration:" -ForegroundColor Cyan
    Write-Host "  Event Log Analysis: $(if ($AnalyzeEventLogs) { 'Yes (' + $EventLogHours + ' hours)' } else { 'No (Quick Scan)' })" -ForegroundColor White
    Write-Host "  Export Results: $(if ($ExportResults) { 'Yes' } else { 'No' })" -ForegroundColor White
    Write-Host "  Processing Mode: $(if ($Parallel -and $PSVersionTable.PSVersion.Major -ge 7) { "Parallel (max $MaxParallelDomains)" } else { 'Sequential' })" -ForegroundColor White

    # Confirm before proceeding
    Write-Host "`nPress any key to start assessment or Ctrl+C to cancel..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    # Initialize results collection
    $forestResults = @{
        ForestName     = $forest.Name
        AssessmentDate = Get-Date
        TotalDomains   = $forest.Domains.Count
        DomainResults  = @()
        OverallStatus  = "Unknown"
        CriticalIssues = 0
        Warnings       = 0
        HealthyDomains = 0
    }

    # Function to assess a single domain
    function Invoke-DomainAssessment {
        param(
            [string]$DomainName,
            [string]$ScriptDir,
            [bool]$AnalyzeLogs,
            [int]$Hours,
            [bool]$Export,
            [bool]$Guidance
        )

        Write-Host "`n$("=" * 80)" -ForegroundColor Yellow
        Write-Host "Assessing Domain: $DomainName" -ForegroundColor Yellow
        Write-Host $("=" * 80) -ForegroundColor Yellow

        # Try to discover a specific DC in this domain for better connectivity
        $serverParam = $null
        try {
            Write-Host "  Discovering Domain Controller for $DomainName..." -ForegroundColor Gray
            $dc = Get-ADDomainController -DomainName $DomainName -Discover -ErrorAction Stop
            # Extract hostname as a simple string (handle arrays, collections, and objects)
            if ($dc.HostName -is [array]) {
                $serverParam = [string]$dc.HostName[0]
            }
            elseif ($dc.HostName.Value) {
                # Handle ADPropertyValueCollection
                $serverParam = [string]$dc.HostName.Value
            }
            else {
                # Direct property access
                $serverParam = [string]$dc.HostName
            }
            Write-Host "  Using DC: $serverParam" -ForegroundColor Green
        }
        catch {
            Write-Host "  Could not discover DC, using domain name directly" -ForegroundColor Yellow
            Write-Host "  Warning: This may fail for child domains if not directly reachable" -ForegroundColor Yellow
        }

        # Build command parameters
        $params = @{}

        if ($serverParam) {
            # Use -Server with the discovered DC hostname
            $params['Server'] = $serverParam
        }
        else {
            # Fall back to -Domain
            $params['Domain'] = $DomainName
        }

        if ($AnalyzeLogs) {
            $params['AnalyzeEventLogs'] = $true
            $params['EventLogHours'] = $Hours
        }

        if ($Export) {
            $params['ExportResults'] = $true
        }

        if ($Guidance) {
            $params['IncludeGuidance'] = $true
        }

        try {
            # Run assessment and capture returned results object
            $assessmentResults = & $ScriptDir @params

            # Parse results (if exported)
            if ($Export) {
                $domainSafe = $DomainName -replace '\.', '_'
                $timestamp = Get-Date -Format "yyyyMMdd"
                $jsonPattern = "DES_RC4_Assessment_${domainSafe}_${timestamp}*.json"

                # Look in Exports folder first, then fallback to script root
                $exportFolder = Join-Path -Path $ScriptDir -ChildPath "Exports"
                $resultFile = Get-ChildItem -Path $exportFolder -Filter $jsonPattern -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1

                if (-not $resultFile) {
                    # Fallback to script root for backwards compatibility
                    $resultFile = Get-ChildItem -Path $ScriptDir -Filter $jsonPattern -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 1
                }

                if ($resultFile) {
                    $result = Get-Content $resultFile.FullName | ConvertFrom-Json
                    return @{
                        Domain = $DomainName
                        Status = $result.OverallStatus
                        Data   = $result
                    }
                }
            }

            # Return results from the script execution
            if ($assessmentResults) {
                return @{
                    Domain = $DomainName
                    Status = $assessmentResults.OverallStatus
                    Data   = $assessmentResults
                }
            }

            return @{
                Domain = $DomainName
                Status = "Completed"
                Data   = $null
            }
        }
        catch {
            Write-Warning "Failed to assess domain $DomainName : $($_.Exception.Message)"
            return @{
                Domain = $DomainName
                Status = "Failed"
                Error  = $_.Exception.Message
                Data   = $null
            }
        }
    }

    # Process domains
    $startTime = Get-Date

    if ($Parallel -and $PSVersionTable.PSVersion.Major -ge 7) {
        Write-Host "`nProcessing domains in parallel (max $MaxParallelDomains concurrent)..." -ForegroundColor Cyan

        $domainResults = $domainList | ForEach-Object -Parallel {
            # Build parameter hashtable for the assessment script
            $params = @{
                Domain = $_
            }

            if ($using:AnalyzeEventLogs) {
                $params['AnalyzeEventLogs'] = $true
                $params['EventLogHours'] = $using:EventLogHours
            }

            if ($using:ExportResults) {
                $params['ExportResults'] = $true
            }

            if ($using:IncludeGuidance) {
                $params['IncludeGuidance'] = $true
            }

            # Run assessment with splatted parameters and capture returned results object
            $assessmentResults = Invoke-RC4Assessment @params

            # Return same structure as Invoke-DomainAssessment for consistency
            @{
                Domain = $_
                Status = if ($assessmentResults) { $assessmentResults.OverallStatus } else { "UNKNOWN" }
                Data   = $assessmentResults
            }
        } -ThrottleLimit $MaxParallelDomains

        $forestResults.DomainResults = $domainResults
    }
    else {
        # Sequential processing
        if ($Parallel -and $PSVersionTable.PSVersion.Major -lt 7) {
            Write-Warning "Parallel processing requires PowerShell 7+. Using sequential mode."
        }

        foreach ($domain in $domainList) {
            $result = Invoke-DomainAssessment -DomainName $domain `
                -ScriptDir $scriptDir -AnalyzeLogs $AnalyzeEventLogs -Hours $EventLogHours `
                -Export $ExportResults -Guidance $IncludeGuidance
            $forestResults.DomainResults += $result
        }
    }

    $endTime = Get-Date
    $duration = $endTime - $startTime

    # Analyze forest-wide results
    Write-Host "`n$("=" * 80)" -ForegroundColor Cyan
    Write-Host "Forest-Wide Assessment Summary" -ForegroundColor Cyan
    Write-Host $("=" * 80) -ForegroundColor Cyan

    foreach ($domainResult in $forestResults.DomainResults) {
        if ($domainResult.Status -eq "CRITICAL") {
            $forestResults.CriticalIssues++
        }
        elseif ($domainResult.Status -eq "WARNING") {
            $forestResults.Warnings++
        }
        elseif ($domainResult.Status -in @("OK", "Completed")) {
            $forestResults.HealthyDomains++
        }
    }

    # Determine overall forest status
    if ($forestResults.CriticalIssues -gt 0) {
        $forestResults.OverallStatus = "CRITICAL"
    }
    elseif ($forestResults.Warnings -gt 0) {
        $forestResults.OverallStatus = "WARNING"
    }
    else {
        $forestResults.OverallStatus = "OK"
    }

    # Display summary
    Write-Host "`nForest: $($forest.Name)" -ForegroundColor White
    Write-Host "Assessment Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor Gray
    Write-Host "`nDomain Status Summary:" -ForegroundColor Cyan
    Write-Host "  $([char]0x2022) Total Domains: $($forestResults.TotalDomains)" -ForegroundColor White
    Write-Host "  $([char]0x2022) Healthy: $($forestResults.HealthyDomains)" -ForegroundColor $(if ($forestResults.HealthyDomains -eq $forestResults.TotalDomains) { "Green" } else { "Gray" })
    Write-Host "  $([char]0x2022) Warnings: $($forestResults.Warnings)" -ForegroundColor $(if ($forestResults.Warnings -gt 0) { "Yellow" } else { "Gray" })
    Write-Host "  $([char]0x2022) Critical: $($forestResults.CriticalIssues)" -ForegroundColor $(if ($forestResults.CriticalIssues -gt 0) { "Red" } else { "Gray" })

    Write-Host "`nPer-Domain Results:" -ForegroundColor Cyan
    foreach ($domainResult in $forestResults.DomainResults) {
        $statusColor = switch ($domainResult.Status) {
            "OK" { "Green" }
            "Completed" { "Green" }
            "WARNING" { "Yellow" }
            "CRITICAL" { "Red" }
            "Failed" { "DarkRed" }
            default { "Gray" }
        }

        $statusIcon = switch ($domainResult.Status) {
            "OK" { [char]0x2713 }  # ✓
            "Completed" { [char]0x2713 }
            "WARNING" { [char]0x26A0 }  # ⚠
            "CRITICAL" { [char]0x2717 }  # ✗
            "Failed" { [char]0x2717 }
            default { [char]0x2022 }  # •
        }

        Write-Host "  $statusIcon $($domainResult.Domain): $($domainResult.Status)" -ForegroundColor $statusColor

        if ($domainResult.Error) {
            Write-Host "    Error: $($domainResult.Error)" -ForegroundColor DarkRed
        }
    }

    # Overall status
    Write-Host "`nOverall Forest Status: " -NoNewline -ForegroundColor White
    $overallColor = switch ($forestResults.OverallStatus) {
        "OK" { "Green" }
        "WARNING" { "Yellow" }
        "CRITICAL" { "Red" }
        default { "Gray" }
    }
    Write-Host $forestResults.OverallStatus -ForegroundColor $overallColor

    # Display Forest-Wide Summary Tables
    Show-ForestSummary -ForestResults $forestResults

    # Export forest-wide results
    if ($ExportResults) {
        Write-Host "`n$("=" * 80)" -ForegroundColor Cyan
        Write-Host "Exporting Forest-Wide Results" -ForegroundColor Cyan
        Write-Host $("=" * 80) -ForegroundColor Cyan

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $forestSafe = $forest.Name -replace '\.', '_'

        # JSON export
        $jsonPath = ".\Forest_Assessment_${forestSafe}_${timestamp}.json"
        $forestResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host "  $([char]0x2713) Forest summary: $jsonPath" -ForegroundColor Green

        # CSV export
        $csvPath = ".\Forest_Assessment_${forestSafe}_${timestamp}.csv"
        $csvData = foreach ($domainResult in $forestResults.DomainResults) {
            [PSCustomObject]@{
                Forest         = $forest.Name
                Domain         = $domainResult.Domain
                Status         = $domainResult.Status
                AssessmentDate = $forestResults.AssessmentDate
            }
        }
        $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "  $([char]0x2713) Domain summary: $csvPath" -ForegroundColor Green
    }

    # Recommendations
    if ($forestResults.CriticalIssues -gt 0 -or $forestResults.Warnings -gt 0) {
        Write-Host "`n$([char]0x26A0)  Recommendations:" -ForegroundColor Yellow

        if ($forestResults.CriticalIssues -gt 0) {
            Write-Host "  $([char]0x2022) CRITICAL: Review individual domain assessments for immediate remediation" -ForegroundColor Red
            Write-Host "  $([char]0x2022) Focus on domains with DES encryption or active RC4 usage" -ForegroundColor Red
        }

        if ($forestResults.Warnings -gt 0) {
            Write-Host "  $([char]0x2022) WARNING: Plan RC4 removal before July 2026 deadline" -ForegroundColor Yellow
            Write-Host "  $([char]0x2022) Review each domain's event logs to identify RC4 usage patterns" -ForegroundColor Yellow
            Write-Host "  $([char]0x2022) Deploy January 2026+ updates and set RC4DefaultDisablementPhase = 1 on all DCs" -ForegroundColor Yellow
        }

        Write-Host "`n  Next Steps:" -ForegroundColor Cyan
        Write-Host "  1. Review individual domain JSON exports for detailed findings and inline fix commands" -ForegroundColor Gray
        Write-Host "  2. Run 'Compare-Assessments.ps1' per domain to track remediation progress" -ForegroundColor Gray
        Write-Host "  3. Set up continuous monitoring with -AnalyzeEventLogs -EventLogHours 168" -ForegroundColor Gray
    }
    else {
        Write-Host "`n$([char]0x2713) Forest is ready for RC4 disablement (July 2026)!" -ForegroundColor Green
    }

    Write-Host "`n$("=" * 80)" -ForegroundColor Cyan
    Write-Host "Forest Assessment Complete" -ForegroundColor Cyan
    Write-Host $("=" * 80)`n -ForegroundColor Cyan

}

