function Get-KdcSvcEventAssessment {
    <#
    .SYNOPSIS
        Assesses KDCSVC system events on Domain Controllers related to CVE-2026-20833.

    .DESCRIPTION
        Connects to each Domain Controller and queries the System event log for KDCSVC events
        that indicate RC4 usage warnings or enforcement actions. Returns a hashtable containing
        event counts per Event ID, detailed event records, queried DC list, a list of DCs that
        failed, and an overall OK or WARNING status. AzureADKerberos proxy objects are
        automatically excluded from the query.

    .PARAMETER ServerParams
        A hashtable of parameters passed through to Active Directory cmdlets. Supports a
        'Server' key to target a specific Domain Controller.

    .EXAMPLE
        $params = @{ Server = 'dc01.contoso.com' }
        $result = Get-KdcSvcEventAssessment -ServerParams $params
        $result.Status
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '')]
    param(
        [hashtable]$ServerParams
    )

    Write-Section "KDCSVC System Event Assessment (CVE-2026-20833)"

    $assessment = @{
        TotalEvents  = 0
        EventCounts  = @{}     # EventID -> count
        EventDetails = @()     # Array of event detail objects
        QueriedDCs   = @()
        FailedDCs    = @()
        Status       = "Unknown"
    }

    try {
        # Get domain info
        if ($ServerParams.ContainsKey('Server')) {
            try {
                $null = Get-ADDomain -Server $ServerParams['Server'] -ErrorAction Stop
            }
            catch {
                throw "Failed to contact Domain Controller '$($ServerParams['Server'])': $($_.Exception.Message)"
            }
        }
        else {
            $null = Get-ADDomain
        }

        # Get all DCs using authoritative DC Locator
        $dcs = @(Get-ADDomainController -Filter * @ServerParams)

        if (-not $dcs -or $dcs.Count -eq 0) {
            Write-Finding -Status "WARNING" -Message "No Domain Controllers found for KDCSVC event check"
            return $assessment
        }

        Write-Finding -Status "INFO" -Message "Checking KDCSVC events 201-209 on $($dcs.Count) Domain Controller(s)"
        Write-Host "  These events indicate RC4 risks related to CVE-2026-20833" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  KDCSVC Event Reference (Provider: KDCSVC, Log: System)" -ForegroundColor White
        Write-Host "  $([char]0x250C)$([string]::new([char]0x2500, 8))$([char]0x252C)$([string]::new([char]0x2500, 14))$([char]0x252C)$([string]::new([char]0x2500, 72))$([char]0x2510)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x2502) Event  $([char]0x2502) RC4 Relation $([char]0x2502) Description                                                            $([char]0x2502)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x251C)$([string]::new([char]0x2500, 8))$([char]0x253C)$([string]::new([char]0x2500, 14))$([char]0x253C)$([string]::new([char]0x2500, 72))$([char]0x2524)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x2502) 201    $([char]0x2502) Direct       $([char]0x2502) KDC rejects request - client only offers RC4, which is not allowed     $([char]0x2502)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x2502) 202    $([char]0x2502) Direct       $([char]0x2502) Client requests unsupported encryption type (RC4 after it was disabled)$([char]0x2502)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x2502) 203    $([char]0x2502) Direct       $([char]0x2502) Account supports RC4 but not AES, while the KDC requires AES           $([char]0x2502)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x2502) 204    $([char]0x2502) Indirect     $([char]0x2502) SPN cannot use the requested encryption type (RC4 often the root cause)$([char]0x2502)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x2502) 205    $([char]0x2502) Direct       $([char]0x2502) DefaultDomainSupportedEncTypes is configured insecurely (includes RC4) $([char]0x2502)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x2502) 206    $([char]0x2502) Direct       $([char]0x2502) Ticket generation failed because RC4 is disabled on the KDC            $([char]0x2502)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x2502) 207    $([char]0x2502) Contextual   $([char]0x2502) Internal KDC error (often appears together with 201-206 events)        $([char]0x2502)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x2502) 208    $([char]0x2502) Direct       $([char]0x2502) Client explicitly requested RC4, and it was rejected                   $([char]0x2502)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x2502) 209    $([char]0x2502) Direct       $([char]0x2502) Ticket cannot be issued because RC4 is no longer allowed by policy     $([char]0x2502)" -ForegroundColor DarkGray
        Write-Host "  $([char]0x2514)$([string]::new([char]0x2500, 8))$([char]0x2534)$([string]::new([char]0x2500, 14))$([char]0x2534)$([string]::new([char]0x2500, 72))$([char]0x2518)" -ForegroundColor DarkGray
        Write-Host "  Ref: https://support.microsoft.com/help/5073381 (CVE-2026-20833)" -ForegroundColor DarkGray
        Write-Host ""

        foreach ($dc in $dcs) {
            $dcName = $dc.HostName
            Write-Host "  $([char]0x2022) Querying $dcName (System log)..." -ForegroundColor Cyan

            try {
                $filterXml = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">
      *[System[Provider[@Name='KDCSVC'] and (EventID &gt;= 201 and EventID &lt;= 209)]]
    </Select>
  </Query>
</QueryList>
"@

                $events = $null
                try {
                    $events = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        param($FilterXml)
                        Get-WinEvent -FilterXml $FilterXml -MaxEvents 500 -ErrorAction Stop
                    } -ArgumentList $filterXml -ErrorAction Stop
                }
                catch {
                    if ($_.Exception.Message -match 'No events were found') {
                        $events = @()
                    }
                    else {
                        # WinRM failed, try RPC
                        Write-Host "    $([char]0x26A0) WinRM unavailable, trying RPC..." -ForegroundColor DarkYellow
                        try {
                            $events = Get-WinEvent -ComputerName $dcName -FilterXml $filterXml -MaxEvents 500 -ErrorAction Stop
                        }
                        catch {
                            if ($_.Exception.Message -match 'No events were found') {
                                $events = @()
                            }
                            else {
                                throw $_
                            }
                        }
                    }
                }

                $assessment.QueriedDCs += $dcName

                if ($events -and $events.Count -gt 0) {
                    Write-Host "    $([char]0x26A0) Found $($events.Count) KDCSVC event(s)" -ForegroundColor Yellow
                    $assessment.TotalEvents += $events.Count

                    foreach ($evt in $events) {
                        $eventId = if ($evt.Id) { $evt.Id } else { $evt.EventID }

                        if (-not $assessment.EventCounts.ContainsKey("$eventId")) {
                            $assessment.EventCounts["$eventId"] = 0
                        }
                        $assessment.EventCounts["$eventId"]++

                        $assessment.EventDetails += @{
                            DC      = $dcName
                            EventID = $eventId
                            Time    = if ($evt.TimeCreated) { $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Unknown' }
                            Message = if ($evt.Message) { ($evt.Message -split "`n")[0] } else { '' }
                        }
                    }
                }
                else {
                    Write-Host "    $([char]0x2713) No KDCSVC events found" -ForegroundColor Green
                }
            }
            catch {
                $assessment.FailedDCs += @{ Name = $dcName; Error = $_.Exception.Message }
                Write-Host "    $([char]0x26A0) Could not query System log on $dcName" -ForegroundColor Yellow
            }
        }

        # Assess results
        if ($assessment.TotalEvents -gt 0) {
            $assessment.Status = "WARNING"
            Write-Host ""
            Write-Finding -Status "WARNING" -Message "KDCSVC events detected - RC4 risks exist (CVE-2026-20833)"
            Write-Host "  Event breakdown:" -ForegroundColor Yellow
            foreach ($kvp in $assessment.EventCounts.GetEnumerator()) {
                $eventDesc = switch ($kvp.Key) {
                    "201" { "KDC rejects request - client only offers RC4" }
                    "202" { "Client requests unsupported encryption type (RC4 after disabled)" }
                    "203" { "Account supports RC4 but not AES, KDC requires AES" }
                    "204" { "SPN cannot use requested encryption type (RC4 often root cause)" }
                    "205" { "DefaultDomainSupportedEncTypes configured insecurely (includes RC4)" }
                    "206" { "Ticket generation failed - RC4 disabled on KDC (Enforcement)" }
                    "207" { "Internal KDC error (contextual, accompanies 201-206)" }
                    "208" { "Client explicitly requested RC4, rejected (Enforcement)" }
                    "209" { "RC4 no longer allowed by policy (Enforcement)" }
                    default { "KDCSVC event" }
                }
                Write-Host "    Event $($kvp.Key): $($kvp.Value) occurrence(s) - $eventDesc" -ForegroundColor Yellow
            }

            # Events 206-208 indicate Enforcement mode is active and blocking
            $blockingEvents = ($assessment.EventCounts.Keys | Where-Object { [int]$_ -ge 206 -and [int]$_ -le 208 })
            if ($blockingEvents) {
                Write-Host "`n  $([char]0x26A0) Enforcement mode is actively blocking RC4 requests" -ForegroundColor Red
                Write-Host "  Affected accounts need migration to AES (0x18) or explicit RC4 exception (0x1C) as last resort" -ForegroundColor Yellow
            }
        }
        else {
            if ($assessment.QueriedDCs.Count -gt 0) {
                $assessment.Status = "OK"
                Write-Finding -Status "OK" -Message "No KDCSVC events found - no RC4 risks detected (CVE-2026-20833)"
                Write-Host "  Note: KDCSVC events require RC4DefaultDisablementPhase >= 1 to be logged" -ForegroundColor Gray
                Write-Host "  If RC4DefaultDisablementPhase is not set or 0, set it to 1 to enable auditing" -ForegroundColor Gray
            }
        }

        if ($assessment.FailedDCs.Count -gt 0) {
            Write-Host "`n  $([char]0x26A0) Could not query System log on $($assessment.FailedDCs.Count) DC(s)" -ForegroundColor Yellow
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -match "Failed to contact Domain Controller '([^']+)'") {
            Write-Finding -Status "CRITICAL" -Message $errorMsg
        }
        else {
            Write-Finding -Status "WARNING" -Message "Error checking KDCSVC events: $errorMsg"
        }
    }

    return $assessment
}
