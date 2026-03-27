function Get-EventLogEncryptionAnalysis {
    <#
    .SYNOPSIS
        Analyses Kerberos event logs on Domain Controllers to detect DES and RC4 ticket usage.

    .DESCRIPTION
        Connects to each Domain Controller and queries Security event logs for Kerberos ticket
        events (Event IDs 4768 and 4769) within a configurable time window. Counts AES, RC4,
        and DES tickets, identifies accounts using weak encryption, and records per-DC
        statistics. Falls back from WinRM to RPC when WinRM is unavailable. Returns a detailed
        hashtable with event counts, affected accounts, and a list of DCs that could not be
        queried.

    .PARAMETER ServerParams
        A hashtable of parameters passed through to Active Directory cmdlets. Supports a
        'Server' key to target a specific Domain Controller.

    .PARAMETER Hours
        The number of hours of event log history to analyse. Defaults to 24.

    .EXAMPLE
        $params = @{ Server = 'dc01.contoso.com' }
        $result = Get-EventLogEncryptionAnalysis -ServerParams $params -Hours 48
        $result.RC4Tickets
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '')]
    param(
        [hashtable]$ServerParams,
        [int]$Hours = 24
    )

    Write-Section "Event Log Analysis - Actual DES/RC4 Usage"

    $assessment = @{
        EventsAnalyzed      = 0
        DESTickets          = 0
        RC4Tickets          = 0
        AESTickets          = 0
        UnknownTickets      = 0
        TimeRange           = $Hours
        DESAccounts         = @()
        RC4Accounts         = @()
        PasswordResetNeeded = @()  # Accounts with AES configured but using RC4 (need password reset)
        Details             = @()
        FailedDCs           = @()  # Track DCs that couldn't be queried
        QueriedDCs          = @()  # Track DCs that were successfully queried
        PerDcStats          = @{}  # Per-DC event counts keyed by hostname
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

        # Get ALL domain controllers using authoritative DC Locator
        Write-Verbose "Discovering all Domain Controllers in $($domainInfo.DNSRoot)"
        $dcs = @(Get-ADDomainController -Filter * @ServerParams)

        if (-not $dcs -or $dcs.Count -eq 0) {
            Write-Finding -Status "WARNING" -Message "No Domain Controllers found for event log analysis"
            return $assessment
        }

        Write-Finding -Status "INFO" -Message "Querying event logs from $($dcs.Count) Domain Controller(s) in $($domainInfo.DNSRoot)"
        Write-Host "  Note: Using WinRM (PowerShell Remoting) for event log queries" -ForegroundColor Gray
        Write-Host "  If this fails, ensure WinRM is enabled on DCs: Enable-PSRemoting -Force" -ForegroundColor Gray

        foreach ($dc in $dcs) {
            $dcName = $dc.HostName
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
                $usedWinRM = $false
                try {
                    # Parse event XML on the remote side to avoid deserialization issues.
                    # Deserialized EventLogRecord objects lose their ToXml() method, making
                    # it impossible to extract EventData fields on the caller side.
                    $events = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        param($FilterXml, $MaxEvents)
                        $rawEvents = Get-WinEvent -FilterXml $FilterXml -MaxEvents $MaxEvents -ErrorAction Stop
                        foreach ($evt in $rawEvents) {
                            $xml = [xml]$evt.ToXml()
                            $data = @{}
                            foreach ($d in $xml.Event.EventData.Data) {
                                $data[$d.Name] = $d.'#text'
                            }
                            [PSCustomObject]@{
                                EventId              = $evt.Id
                                TargetUserName       = $data['TargetUserName']
                                TicketEncryptionType = $data['TicketEncryptionType']
                                ServiceName          = $data['ServiceName']
                            }
                        }
                    } -ArgumentList $filterXml, 1000 -ErrorAction Stop
                    $usedWinRM = $true
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
                    $assessment.PerDcStats[$dcName] = @{ EventsAnalyzed = 0; RC4Tickets = 0; DESTickets = 0; AESTickets = 0 }
                    continue
                }

                if ($events) {
                    Write-Host "    $([char]0x2713) Retrieved $($events.Count) events from $dcName" -ForegroundColor Green
                    $assessment.EventsAnalyzed += $events.Count
                    $assessment.QueriedDCs += $dcName  # Track successfully queried DC
                    $dcStats = @{ EventsAnalyzed = $events.Count; RC4Tickets = 0; DESTickets = 0; AESTickets = 0 }

                    foreach ($evt in $events) {
                        $encType = $null
                        $account = $null

                        if ($usedWinRM) {
                            # Events were pre-parsed on the remote side
                            if ($evt.TicketEncryptionType) {
                                $encType = [int]$evt.TicketEncryptionType
                                $account = $evt.TargetUserName
                            }
                        }
                        else {
                            # RPC fallback: events are native EventLogRecord objects
                            $eventXml = $evt.ToXml()
                            $xml = [xml]$eventXml
                            $eventData = @{}
                            foreach ($data in $xml.Event.EventData.Data) {
                                $eventData[$data.Name] = $data.'#text'
                            }
                            if ($eventData['TicketEncryptionType']) {
                                $encType = [int]$eventData['TicketEncryptionType']
                                $account = $eventData['TargetUserName']
                            }
                        }

                        if ($null -eq $encType) {
                            continue
                        }

                        # Categorize by encryption type
                        switch ($encType) {
                            { $_ -in @(0x1, 0x3) } {
                                # DES
                                $assessment.DESTickets++
                                $dcStats.DESTickets++
                                if ($account -and $account -notin $assessment.DESAccounts) {
                                    $assessment.DESAccounts += $account
                                }
                            }
                            0x17 {
                                # RC4
                                $assessment.RC4Tickets++
                                $dcStats.RC4Tickets++
                                if ($account -and $account -notin $assessment.RC4Accounts) {
                                    $assessment.RC4Accounts += $account
                                }
                            }
                            { $_ -in @(0x11, 0x12) } {
                                # AES
                                $assessment.AESTickets++
                                $dcStats.AESTickets++
                            }
                            default {
                                $assessment.UnknownTickets++
                            }
                        }
                    }
                    $assessment.PerDcStats[$dcName] = $dcStats
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
