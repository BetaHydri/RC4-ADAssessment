function Show-AssessmentSummary {
    <#
    .SYNOPSIS
        Displays formatted summary tables for a completed RC4/DES domain assessment.

    .DESCRIPTION
        Renders console-formatted summary tables from a completed assessment results hashtable,
        including Domain Controller encryption status, account findings (KRBTGT, DES-flag
        accounts, RC4-only service accounts), event log statistics, trust encryption status,
        and KDC registry configuration. Failed DC lists are shown when present.

    .PARAMETER Results
        The assessment results hashtable returned by Invoke-DomainAssessment or
        Invoke-RC4Assessment.

    .EXAMPLE
        $results = Invoke-RC4Assessment -DomainName "contoso.com"
        Show-AssessmentSummary -Results $results
    #>
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
                $gpoEnc = $Results.DomainControllers.GPOEncryptionTypes
                if ($gpoEnc -band 0x3) { "CRITICAL" }      # DES enabled
                elseif ($gpoEnc -band 0x4) { "WARNING" }    # RC4 enabled
                else { "OK" }
            }
            else { "Not Configured" }

            $dcTable += [PSCustomObject]@{
                'Domain Controller' = $dc.Name
                'Type'              = if ($dc.IsReadOnly) { 'RODC' } else { 'RWDC' }
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
        if ($Results.DomainControllers.RODCCount -gt 0) {
            Write-Host "    Read-Only DCs (RODCs): $($Results.DomainControllers.RODCCount)" -ForegroundColor Cyan
        }

        # Display AzureADKerberos separately if present
        if ($Results.DomainControllers.AzureADKerberos) {
            $aadK = $Results.DomainControllers.AzureADKerberos
            Write-Host "`n  ENTRA KERBEROS PROXY (excluded from DC counts)" -ForegroundColor DarkCyan
            Write-Host ("  " + ([string]([char]0x2500) * 60)) -ForegroundColor DarkGray
            Write-Host "    Name:             $($aadK.Name)" -ForegroundColor DarkCyan
            Write-Host "    Encryption Types: $($aadK.EncryptionTypes)" -ForegroundColor DarkCyan
            Write-Host "    Status:           $($aadK.Status)" -ForegroundColor DarkCyan
            Write-Host "    $([char]0x24D8)  This is a Microsoft Entra ID (Azure AD) Kerberos proxy object." -ForegroundColor Gray
            Write-Host "    It is NOT a real Domain Controller. Its encryption settings are managed by Entra ID." -ForegroundColor Gray
            Write-Host "    Do not manually modify its encryption settings." -ForegroundColor Gray
            Write-Host "    $([char]0x26A0) Its krbtgt keys are NOT auto-rotated! Rotate regularly:" -ForegroundColor Yellow
            Write-Host "    # Install module (one-time):" -ForegroundColor Gray
            Write-Host "    PS> [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12" -ForegroundColor Green
            Write-Host "    PS> Install-Module -Name AzureADHybridAuthenticationManagement -AllowClobber" -ForegroundColor Green
            Write-Host "    # Rotate keys:" -ForegroundColor Gray
            Write-Host "    PS> `$cloudCred = Get-Credential -Message 'UPN of Hybrid Identity Administrator'" -ForegroundColor Green
            Write-Host "    PS> `$domainCred = Get-Credential -Message 'Domain\User of Domain Admins group'" -ForegroundColor Green
            Write-Host "    PS> Set-AzureADKerberosServer -Domain <domain> -CloudCredential `$cloudCred -DomainCredential `$domainCred -RotateServerKey" -ForegroundColor Green
            Write-Host "    See: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-on-premises" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  No Domain Controller data available" -ForegroundColor Yellow
    }

    # 1b. RODC KRBTGT Account Summary
    if ($Results.Accounts.RODCKrbtgtAccounts -and $Results.Accounts.RODCKrbtgtAccounts.Count -gt 0) {
        Write-Host "`n`n  RODC KRBTGT ACCOUNT SUMMARY" -ForegroundColor Cyan
        Write-Host ("  " + ([string]([char]0x2500) * 100)) -ForegroundColor DarkGray

        $rodcTable = @()
        foreach ($rodcK in $Results.Accounts.RODCKrbtgtAccounts) {
            $pwdDateStr = if ($rodcK.PasswordLastSet) { $rodcK.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Unknown' }
            $rodcTable += [PSCustomObject]@{
                'Account'          = $rodcK.Name
                'Status'           = $rodcK.Status
                'Password Age'     = "$($rodcK.PasswordAgeDays) days"
                'Password Last Set' = $pwdDateStr
                'Encryption Types' = if ($rodcK.EncryptionTypes) { $rodcK.EncryptionTypes } else { 'Not Set (domain default)' }
                'Enabled'          = $rodcK.Enabled
            }
        }

        $rodcTable | Format-Table -AutoSize | Out-String -Stream | ForEach-Object {
            if ($_ -match "CRITICAL") {
                Write-Host "  $_" -ForegroundColor Red
            }
            elseif ($_ -match "WARNING") {
                Write-Host "  $_" -ForegroundColor Yellow
            }
            elseif ($_ -match "OK") {
                Write-Host "  $_" -ForegroundColor Green
            }
            elseif ($_ -match "Account|^-+$") {
                Write-Host "  $_" -ForegroundColor Cyan
            }
            else {
                Write-Host "  $_"
            }
        }

        Write-Host "  $([char]0x24D8)  Each RODC has its own krbtgt_XXXXX account used to sign tickets for cached accounts." -ForegroundColor Gray
        Write-Host "  Rotate these passwords independently from the domain-wide KRBTGT account." -ForegroundColor Gray
        Write-Host "  Use: Reset-ComputerMachinePassword on the RODC, or reset via AD Users & Computers." -ForegroundColor Gray
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
                $dcStats = if ($Results.EventLogs.PerDcStats -and $Results.EventLogs.PerDcStats[$dcName]) { $Results.EventLogs.PerDcStats[$dcName] } else { $null }
                $eventTable += [PSCustomObject]@{
                    'Domain Controller' = $dcName
                    'Status'            = 'Success'
                    'Events Analyzed'   = if ($dcStats) { $dcStats.EventsAnalyzed } else { 0 }
                    'RC4 Tickets'       = if ($dcStats) { $dcStats.RC4Tickets } else { 0 }
                    'DES Tickets'       = if ($dcStats) { $dcStats.DESTickets } else { 0 }
                    'RC4 SessKey'       = if ($dcStats) { $dcStats.SessionKeyRC4 } else { 0 }
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
                    'RC4 SessKey'       = 0
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
            if ($Results.EventLogs.SessionKeyRC4 -and $Results.EventLogs.SessionKeyRC4 -gt 0) {
                Write-Host "    RC4 Session Keys Detected: $($Results.EventLogs.SessionKeyRC4)" -ForegroundColor Yellow
            }
            if ($Results.EventLogs.SessionKeyDES -and $Results.EventLogs.SessionKeyDES -gt 0) {
                Write-Host "    DES Session Keys Detected: $($Results.EventLogs.SessionKeyDES)" -ForegroundColor Red
            }
            if ($Results.EventLogs.FailedDCs.Count -gt 0) {
                Write-Host "    Failed DC Queries: $($Results.EventLogs.FailedDCs.Count)" -ForegroundColor Yellow
            }
            if ($Results.EventLogs.PasswordResetNeeded -and $Results.EventLogs.PasswordResetNeeded.Count -gt 0) {
                Write-Host "    RC4 Tickets Despite AES Config: $($Results.EventLogs.PasswordResetNeeded.Count) account(s) - password may predate DFL 2008 or account migrated" -ForegroundColor Yellow
                foreach ($prn in $Results.EventLogs.PasswordResetNeeded) {
                    $pwdAge = if ($prn.PasswordAgeDays -ge 0) { "$($prn.PasswordAgeDays)d" } else { "?" }
                    Write-Host "      $([char]0x2022) $($prn.Name) ($($prn.EncryptionTypes), pwd age: $pwdAge)" -ForegroundColor DarkYellow
                }
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
            'Last Logon'       = 'N/A'
            'Encryption Types' = if ($Results.Accounts.KRBTGT.EncryptionTypes) { $Results.Accounts.KRBTGT.EncryptionTypes } else { "Not Set" }
        }

        # DES flag accounts
        foreach ($acct in $Results.Accounts.DESFlagAccounts) {
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $acct.Name
                'Type'             = 'USE_DES_KEY_ONLY'
                'Status'           = 'CRITICAL'
                'Password Age'     = if ($acct.PasswordLastSet) { "$([int]((Get-Date) - $acct.PasswordLastSet).TotalDays) days" } else { "Unknown" }
                'Last Logon'       = if ($acct.LastLogon) { "$($acct.LastLogon.ToString('yyyy-MM-dd')) ($($acct.LastLogonDaysAgo)d)" } else { "Never" }
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
                'Last Logon'       = if ($svc.LastLogon) { "$($svc.LastLogon.ToString('yyyy-MM-dd')) ($($svc.LastLogonDaysAgo)d)" } else { "Never" }
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
                    'Last Logon'       = if ($svc.LastLogon) { "$($svc.LastLogon.ToString('yyyy-MM-dd')) ($($svc.LastLogonDaysAgo)d)" } else { "Never" }
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
                'Last Logon'       = if ($msa.LastLogon) { "$($msa.LastLogon.ToString('yyyy-MM-dd')) ($($msa.LastLogonDaysAgo)d)" } else { "Never" }
                'Encryption Types' = $msa.EncryptionTypes
            }
        }

        # DES-enabled accounts
        foreach ($des in $Results.Accounts.DESEnabledAccounts) {
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $des.Name
                'Type'             = "DES-Enabled $($des.AccountType)"
                'Status'           = 'WARNING'
                'Password Age'     = if ($des.PasswordAgeDays) { "$($des.PasswordAgeDays) days" } elseif ($des.PasswordLastSet) { "$([int]((Get-Date) - $des.PasswordLastSet).TotalDays) days" } else { "Auto-managed" }
                'Last Logon'       = if ($des.LastLogon) { "$($des.LastLogon.ToString('yyyy-MM-dd')) ($($des.LastLogonDaysAgo)d)" } else { "Never" }
                'Encryption Types' = $des.EncryptionTypes
            }
        }

        # RC4 exception accounts (RC4 + AES)
        foreach ($exc in $Results.Accounts.RC4ExceptionAccounts) {
            $excType = if ($exc.AccountType) { "RC4 Exception $($exc.AccountType)" } else { 'RC4 Exception' }
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $exc.Name
                'Type'             = $excType
                'Status'           = 'WARNING'
                'Password Age'     = if ($exc.PasswordAgeDays -and $exc.PasswordAgeDays -ge 0) { "$($exc.PasswordAgeDays) days" } elseif ($exc.PasswordLastSet) { "$([int]((Get-Date) - $exc.PasswordLastSet).TotalDays) days" } else { "Auto-managed" }
                'Last Logon'       = if ($exc.LastLogon) { "$($exc.LastLogon.ToString('yyyy-MM-dd')) ($($exc.LastLogonDaysAgo)d)" } else { "Never" }
                'Encryption Types' = $exc.EncryptionTypes
            }
        }

        # Missing AES key accounts
        foreach ($acct in $Results.Accounts.MissingAESKeyAccounts) {
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $acct.Name
                'Type'             = "Missing AES Keys"
                'Status'           = 'WARNING'
                'Password Age'     = "$($acct.PasswordAgeDays) days"
                'Last Logon'       = if ($acct.LastLogon) { "$($acct.LastLogon.ToString('yyyy-MM-dd')) ($($acct.LastLogonDaysAgo)d)" } else { "Never" }
                'Encryption Types' = 'Not Set'
            }
        }

        # DeepScan: RC4-only users (no SPN)
        foreach ($u in $Results.Accounts.DeepScanRC4OnlyUsers) {
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $u.Name
                'Type'             = 'DeepScan RC4-Only User'
                'Status'           = 'CRITICAL'
                'Password Age'     = if ($u.PasswordLastSet) { "$([int]((Get-Date) - $u.PasswordLastSet).TotalDays) days" } else { "Unknown" }
                'Last Logon'       = if ($u.LastLogon) { "$($u.LastLogon.ToString('yyyy-MM-dd')) ($($u.LastLogonDaysAgo)d)" } else { "Never" }
                'Encryption Types' = $u.EncryptionTypes
            }
        }

        # DeepScan: DES-only users (no SPN)
        foreach ($u in $Results.Accounts.DeepScanDESOnlyUsers) {
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $u.Name
                'Type'             = 'DeepScan DES-Only User'
                'Status'           = 'CRITICAL'
                'Password Age'     = if ($u.PasswordLastSet) { "$([int]((Get-Date) - $u.PasswordLastSet).TotalDays) days" } else { "Unknown" }
                'Last Logon'       = if ($u.LastLogon) { "$($u.LastLogon.ToString('yyyy-MM-dd')) ($($u.LastLogonDaysAgo)d)" } else { "Never" }
                'Encryption Types' = $u.EncryptionTypes
            }
        }

        # DeepScan: DES-enabled users (no SPN)
        foreach ($u in $Results.Accounts.DeepScanDESEnabledUsers) {
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $u.Name
                'Type'             = 'DeepScan DES-Enabled User'
                'Status'           = 'WARNING'
                'Password Age'     = if ($u.PasswordLastSet) { "$([int]((Get-Date) - $u.PasswordLastSet).TotalDays) days" } else { "Unknown" }
                'Last Logon'       = if ($u.LastLogon) { "$($u.LastLogon.ToString('yyyy-MM-dd')) ($($u.LastLogonDaysAgo)d)" } else { "Never" }
                'Encryption Types' = $u.EncryptionTypes
            }
        }

        # DeepScan: RC4-exception users (no SPN)
        foreach ($u in $Results.Accounts.DeepScanRC4ExceptionUsers) {
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $u.Name
                'Type'             = 'DeepScan RC4 Exception User'
                'Status'           = 'WARNING'
                'Password Age'     = if ($u.PasswordLastSet) { "$([int]((Get-Date) - $u.PasswordLastSet).TotalDays) days" } else { "Unknown" }
                'Last Logon'       = if ($u.LastLogon) { "$($u.LastLogon.ToString('yyyy-MM-dd')) ($($u.LastLogonDaysAgo)d)" } else { "Never" }
                'Encryption Types' = $u.EncryptionTypes
            }
        }

        # DeepScan: Problematic computers
        foreach ($c in $Results.Accounts.DeepScanComputersProblematic) {
            $krbtgtTable += [PSCustomObject]@{
                'Account'          = $c.Name
                'Type'             = 'DeepScan Problematic Computer'
                'Status'           = 'WARNING'
                'Password Age'     = if ($c.PasswordLastSet) { "$([int]((Get-Date) - $c.PasswordLastSet).TotalDays) days" } else { "Unknown" }
                'Last Logon'       = if ($c.LastLogon) { "$($c.LastLogon.ToString('yyyy-MM-dd')) ($($c.LastLogonDaysAgo)d)" } else { "Never" }
                'Encryption Types' = $c.EncryptionTypes
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
        if ($Results.Accounts.TotalDESEnabled -gt 0) {
            Write-Host "    DES-Enabled Accounts: $($Results.Accounts.TotalDESEnabled)" -ForegroundColor Yellow
        }
        if ($Results.Accounts.TotalRC4Exception -gt 0) {
            Write-Host "    RC4 Exception Accounts: $($Results.Accounts.TotalRC4Exception)" -ForegroundColor Yellow
        }
        if ($Results.Accounts.TotalStaleSvc -gt 0) {
            Write-Host "    Stale Password Service Accounts: $($Results.Accounts.TotalStaleSvc)" -ForegroundColor Yellow
        }
        if ($Results.Accounts.TotalMissingAES -gt 0) {
            Write-Host "    Missing AES Key Accounts: $($Results.Accounts.TotalMissingAES)" -ForegroundColor Yellow
        }
        if ($Results.Accounts.TotalDeepScanRC4OnlyUsers -gt 0) {
            Write-Host "    [DeepScan] RC4-Only Users: $($Results.Accounts.TotalDeepScanRC4OnlyUsers)" -ForegroundColor Red
        }
        if ($Results.Accounts.TotalDeepScanDESOnlyUsers -gt 0) {
            Write-Host "    [DeepScan] DES-Only Users: $($Results.Accounts.TotalDeepScanDESOnlyUsers)" -ForegroundColor Red
        }
        if ($Results.Accounts.TotalDeepScanDESEnabledUsers -gt 0) {
            Write-Host "    [DeepScan] DES-Enabled Users: $($Results.Accounts.TotalDeepScanDESEnabledUsers)" -ForegroundColor Yellow
        }
        if ($Results.Accounts.TotalDeepScanRC4ExceptionUsers -gt 0) {
            Write-Host "    [DeepScan] RC4 Exception Users: $($Results.Accounts.TotalDeepScanRC4ExceptionUsers)" -ForegroundColor Yellow
        }
        if ($Results.Accounts.DeepScanComputersOSDefault -gt 0) {
            Write-Host "    [DeepScan] Computers OS-Default (0x1C): $($Results.Accounts.DeepScanComputersOSDefault) (deploy AES-only GPO)" -ForegroundColor Cyan
        }
        if ($Results.Accounts.TotalDeepScanComputersProblematic -gt 0) {
            Write-Host "    [DeepScan] Problematic Computers: $($Results.Accounts.TotalDeepScanComputersProblematic)" -ForegroundColor Yellow
        }
    }

    Write-Host ""
}
