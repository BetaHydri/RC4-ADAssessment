function Show-ForestSummary {
    <#
    .SYNOPSIS
        Displays forest-wide summary tables aggregating assessment results across all domains.

    .DESCRIPTION
        Renders consolidated console-formatted summary tables from a forest-level assessment
        result, combining Domain Controller, event log, and trust data across all assessed
        domains. Provides a cross-domain view of RC4/DES exposure within the Active Directory
        forest.

    .PARAMETER ForestResults
        The forest assessment results hashtable returned by Invoke-RC4ForestAssessment.

    .EXAMPLE
        $forestResults = Invoke-RC4ForestAssessment
        Show-ForestSummary -ForestResults $forestResults
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ForestResults
    )

    Write-Host "`n$("=" * 100)" -ForegroundColor Cyan
    Write-Host "FOREST-WIDE SUMMARY TABLES" -ForegroundColor Cyan
    Write-Host $("=" * 100) -ForegroundColor Cyan

    # Aggregate data from all domains
    $allDCs = @()
    $allEvents = @()
    $allTrusts = @()

    foreach ($domainResult in $ForestResults.DomainResults) {
        if ($domainResult.Data) {
            $domainName = $domainResult.Domain

            # Collect DC data
            if ($domainResult.Data.DomainControllers.Details) {
                foreach ($dc in $domainResult.Data.DomainControllers.Details) {
                    $status = "OK"
                    if ($dc.EncryptionTypes -match "DES") {
                        $status = "CRITICAL"
                    }
                    elseif ($dc.EncryptionTypes -match "RC4") {
                        $status = "WARNING"
                    }

                    $allDCs += [PSCustomObject]@{
                        'Domain'            = $domainName
                        'Domain Controller' = $dc.Name
                        'Status'            = $status
                        'Encryption Types'  = $dc.EncryptionTypes
                        'Operating System'  = $dc.OperatingSystem
                    }
                }
            }

            # Collect event log data
            if ($domainResult.Data.EventLogs) {
                $eventData = $domainResult.Data.EventLogs

                # Successfully queried DCs
                if ($eventData.QueriedDCs) {
                    foreach ($dcName in $eventData.QueriedDCs) {
                        $allEvents += [PSCustomObject]@{
                            'Domain'            = $domainName
                            'Domain Controller' = $dcName
                            'Status'            = 'Success'
                            'Events'            = if ($eventData.EventsAnalyzed) { $eventData.EventsAnalyzed } else { 0 }
                            'RC4'               = if ($eventData.RC4Tickets) { $eventData.RC4Tickets } else { 0 }
                            'DES'               = if ($eventData.DESTickets) { $eventData.DESTickets } else { 0 }
                            'RC4 SessKey'       = if ($eventData.SessionKeyRC4) { $eventData.SessionKeyRC4 } else { 0 }
                        }
                    }
                }

                # Failed DCs
                if ($eventData.FailedDCs -and $eventData.FailedDCs.Count -gt 0) {
                    foreach ($failed in $eventData.FailedDCs) {
                        $allEvents += [PSCustomObject]@{
                            'Domain'            = $domainName
                            'Domain Controller' = $failed.Name
                            'Status'            = 'Failed'
                            'Events'            = 0
                            'RC4'               = 0
                            'DES'               = 0
                            'RC4 SessKey'       = 0
                        }
                    }
                }
            }

            # Collect trust data
            if ($domainResult.Data.Trusts.Details) {
                foreach ($trust in $domainResult.Data.Trusts.Details) {
                    $risk = "LOW"
                    if ($trust.EncryptionTypes -match "DES") {
                        $risk = "CRITICAL"
                    }
                    elseif ($trust.EncryptionTypes -match "RC4") {
                        $risk = "HIGH"
                    }

                    $allTrusts += [PSCustomObject]@{
                        'Domain'           = $domainName
                        'Trust Name'       = $trust.Name
                        'Direction'        = $trust.Direction
                        'Encryption Types' = $trust.EncryptionTypes
                        'Risk'             = $risk
                    }
                }
            }
        }
    }

    # 1. Domain Controller Summary (grouped by domain)
    if ($allDCs.Count -gt 0) {
        Write-Host "`n  ALL DOMAIN CONTROLLERS ACROSS FOREST" -ForegroundColor Yellow
        Write-Host ("  " + ([string]([char]0x2500) * 100)) -ForegroundColor DarkGray

        # Group by domain
        $dcsByDomain = $allDCs | Group-Object -Property Domain | Sort-Object Name

        foreach ($domainGroup in $dcsByDomain) {
            Write-Host "`n  Domain: $($domainGroup.Name)" -ForegroundColor Cyan

            $domainGroup.Group | Format-Table -Property @{Label = 'Domain Controller'; Expression = { $_.'Domain Controller' } },
            Status,
            @{Label = 'Encryption Types'; Expression = { $_.'Encryption Types' } },
            @{Label = 'Operating System'; Expression = { $_.'Operating System' } } -AutoSize | Out-String -Stream | ForEach-Object {
                if ($_ -match "CRITICAL") {
                    Write-Host "    $_" -ForegroundColor Red
                }
                elseif ($_ -match "WARNING") {
                    Write-Host "    $_" -ForegroundColor Yellow
                }
                elseif ($_ -match "OK") {
                    Write-Host "    $_" -ForegroundColor Green
                }
                elseif ($_ -match "Domain Controller|^-+$") {
                    Write-Host "    $_" -ForegroundColor Cyan
                }
                else {
                    Write-Host "    $_"
                }
            }
        }

        # Overall DC statistics
        Write-Host "`n  Forest-Wide DC Statistics:" -ForegroundColor Yellow
        $totalDCs = $allDCs.Count
        $criticalDCs = ($allDCs | Where-Object { $_.Status -eq "CRITICAL" }).Count
        $warningDCs = ($allDCs | Where-Object { $_.Status -eq "WARNING" }).Count
        $okDCs = ($allDCs | Where-Object { $_.Status -eq "OK" }).Count

        Write-Host "    Total DCs: $totalDCs" -ForegroundColor White
        if ($criticalDCs -gt 0) {
            Write-Host "    CRITICAL (DES): $criticalDCs" -ForegroundColor Red
        }
        if ($warningDCs -gt 0) {
            Write-Host "    WARNING (RC4): $warningDCs" -ForegroundColor Yellow
        }
        if ($okDCs -gt 0) {
            Write-Host "    OK (AES): $okDCs" -ForegroundColor Green
        }
    }

    # 2. Event Log Summary (grouped by domain)
    if ($allEvents.Count -gt 0) {
        Write-Host "`n`n  EVENT LOG ANALYSIS - ALL DOMAINS" -ForegroundColor Yellow
        Write-Host ("  " + ([string]([char]0x2500) * 100)) -ForegroundColor DarkGray

        # Group by domain
        $eventsByDomain = $allEvents | Group-Object -Property Domain | Sort-Object Name

        foreach ($domainGroup in $eventsByDomain) {
            Write-Host "`n  Domain: $($domainGroup.Name)" -ForegroundColor Cyan

            $domainGroup.Group | Format-Table -Property @{Label = 'Domain Controller'; Expression = { $_.'Domain Controller' } },
            Status,
            Events,
            RC4,
            DES -AutoSize | Out-String -Stream | ForEach-Object {
                if ($_ -match "Failed") {
                    Write-Host "    $_" -ForegroundColor Red
                }
                elseif ($_ -match "Success") {
                    Write-Host "    $_" -ForegroundColor Green
                }
                elseif ($_ -match "Domain Controller|^-+$") {
                    Write-Host "    $_" -ForegroundColor Cyan
                }
                else {
                    Write-Host "    $_"
                }
            }
        }

        # Overall event statistics
        Write-Host "`n  Forest-Wide Event Statistics:" -ForegroundColor Yellow
        $totalEvents = ($allEvents | Measure-Object -Property Events -Sum).Sum
        $totalRC4 = ($allEvents | Measure-Object -Property RC4 -Sum).Sum
        $totalDES = ($allEvents | Measure-Object -Property DES -Sum).Sum
        $failedDCs = ($allEvents | Where-Object { $_.Status -eq "Failed" }).Count

        Write-Host "    Total Events Analyzed: $totalEvents" -ForegroundColor White
        if ($totalRC4 -gt 0) {
            Write-Host "    RC4 Tickets: $totalRC4" -ForegroundColor Red
        }
        if ($totalDES -gt 0) {
            Write-Host "    DES Tickets: $totalDES" -ForegroundColor Red
        }
        if ($failedDCs -gt 0) {
            Write-Host "    Failed Queries: $failedDCs" -ForegroundColor Yellow
        }

        # Password Reset Needed correlation (v2.8.1+)
        $totalPRN = 0
        foreach ($domainResult in $DomainResults) {
            if ($domainResult.Data.EventLogs.PasswordResetNeeded) {
                $totalPRN += @($domainResult.Data.EventLogs.PasswordResetNeeded).Count
            }
        }
        if ($totalPRN -gt 0) {
            Write-Host "    Password Reset Needed: $totalPRN account(s) have AES configured but use RC4" -ForegroundColor Yellow
        }
    }

    # 3. Trust Summary (grouped by domain)
    if ($allTrusts.Count -gt 0) {
        Write-Host "`n`n  TRUST ENCRYPTION - ALL DOMAINS" -ForegroundColor Yellow
        Write-Host ("  " + ([string]([char]0x2500) * 100)) -ForegroundColor DarkGray

        # Group by domain
        $trustsByDomain = $allTrusts | Group-Object -Property Domain | Sort-Object Name

        foreach ($domainGroup in $trustsByDomain) {
            Write-Host "`n  Domain: $($domainGroup.Name)" -ForegroundColor Cyan

            $domainGroup.Group | Format-Table -Property @{Label = 'Trust Name'; Expression = { $_.'Trust Name' } },
            Direction,
            @{Label = 'Encryption Types'; Expression = { $_.'Encryption Types' } },
            Risk -AutoSize | Out-String -Stream | ForEach-Object {
                if ($_ -match "CRITICAL") {
                    Write-Host "    $_" -ForegroundColor Red
                }
                elseif ($_ -match "HIGH") {
                    Write-Host "    $_" -ForegroundColor Yellow
                }
                elseif ($_ -match "LOW") {
                    Write-Host "    $_" -ForegroundColor Green
                }
                elseif ($_ -match "Trust Name|^-+$") {
                    Write-Host "    $_" -ForegroundColor Cyan
                }
                else {
                    Write-Host "    $_"
                }
            }
        }

        # Overall trust statistics
        Write-Host "`n  Forest-Wide Trust Statistics:" -ForegroundColor Yellow
        $totalTrusts = $allTrusts.Count
        $criticalTrusts = ($allTrusts | Where-Object { $_.Risk -eq "CRITICAL" }).Count
        $highRiskTrusts = ($allTrusts | Where-Object { $_.Risk -eq "HIGH" }).Count
        $lowRiskTrusts = ($allTrusts | Where-Object { $_.Risk -eq "LOW" }).Count

        Write-Host "    Total Trusts: $totalTrusts" -ForegroundColor White
        if ($criticalTrusts -gt 0) {
            Write-Host "    CRITICAL (DES): $criticalTrusts" -ForegroundColor Red
        }
        if ($highRiskTrusts -gt 0) {
            Write-Host "    HIGH (RC4): $highRiskTrusts" -ForegroundColor Yellow
        }
        if ($lowRiskTrusts -gt 0) {
            Write-Host "    LOW (AES): $lowRiskTrusts" -ForegroundColor Green
        }
    }

    Write-Host "`n$("=" * 100)`n" -ForegroundColor Cyan
}
