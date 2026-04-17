function Get-AccountEncryptionAssessment {
    <#
    .SYNOPSIS
        Assesses Kerberos encryption configuration for KRBTGT and service accounts in a domain.

    .DESCRIPTION
        Queries Active Directory for the KRBTGT account password age and encryption type,
        as well as service accounts that are configured with DES-only or RC4-only encryption,
        accounts with the DES flag set, accounts missing AES keys (password not changed since
        AES was introduced), and accounts using RC4 exception flags. Returns a detailed
        hashtable with status and findings for each category.

    .PARAMETER ServerParams
        A hashtable of parameters passed through to Active Directory cmdlets. Supports a
        'Server' key to target a specific Domain Controller.

    .PARAMETER DeepScan
        When specified, extends the assessment to scan all enabled user accounts (not just
        those with SPNs) and all enabled computer accounts (excluding DCs) for RC4/DES
        encryption configurations. Computer accounts with the OS-default value 0x1C are
        reported as an INFO summary count; others are listed individually as WARNING.

    .EXAMPLE
        $params = @{ Server = 'dc01.contoso.com' }
        $result = Get-AccountEncryptionAssessment -ServerParams $params
        $result.KRBTGT.Status
    #>
    param(
        [hashtable]$ServerParams,

        [switch]$DeepScan
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
        RC4ExceptionAccounts   = @()
        DESEnabledAccounts     = @()
        StaleServiceAccounts   = @()
        MissingAESKeyAccounts  = @()
        TotalDESFlag           = 0
        TotalRC4OnlySvc        = 0
        TotalRC4OnlyMSA        = 0
        TotalRC4Exception      = 0
        TotalDESEnabled        = 0
        TotalStaleSvc          = 0
        TotalMissingAES                   = 0
        RODCKrbtgtAccounts                = @()
        TotalRODCKrbtgt                   = 0
        Details                           = @()
        DeepScanRC4OnlyUsers              = @()
        DeepScanDESOnlyUsers              = @()
        DeepScanDESEnabledUsers           = @()
        DeepScanRC4ExceptionUsers         = @()
        DeepScanComputersProblematic      = @()
        DeepScanComputersOSDefault        = 0
        TotalDeepScanRC4OnlyUsers         = 0
        TotalDeepScanDESOnlyUsers         = 0
        TotalDeepScanDESEnabledUsers      = 0
        TotalDeepScanRC4ExceptionUsers    = 0
        TotalDeepScanComputersProblematic = 0
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
        # 1b. RODC KRBTGT Accounts (krbtgt_XXXXX)
        # ────────────────────────────────────────────────
        Write-Host "`n  Checking RODC KRBTGT accounts (krbtgt_*)..." -ForegroundColor Cyan

        try {
            $rodcKrbtgtAccounts = @(Get-ADUser -Filter 'Name -like "krbtgt_*"' `
                -Properties pwdLastSet, 'msDS-SupportedEncryptionTypes', PasswordLastSet, WhenChanged, Enabled @ServerParams -ErrorAction Stop)

            if ($rodcKrbtgtAccounts.Count -gt 0) {
                $assessment.TotalRODCKrbtgt = $rodcKrbtgtAccounts.Count
                Write-Finding -Status "INFO" -Message "Found $($rodcKrbtgtAccounts.Count) RODC KRBTGT account(s)"

                foreach ($rodcKrbtgt in $rodcKrbtgtAccounts) {
                    $pwdLastSet = $rodcKrbtgt.PasswordLastSet
                    if (-not $pwdLastSet -and $rodcKrbtgt.pwdLastSet) {
                        $pwdLastSet = [DateTime]::FromFileTime($rodcKrbtgt.pwdLastSet)
                    }

                    $passwordAgeDays = if ($pwdLastSet) { ((Get-Date) - $pwdLastSet).Days } else { -1 }
                    $encValue = $rodcKrbtgt.'msDS-SupportedEncryptionTypes'
                    $encTypes = Get-EncryptionTypeString -Value $encValue

                    $status = "OK"
                    if ($passwordAgeDays -lt 0) {
                        $status = "UNKNOWN"
                    }
                    elseif ($passwordAgeDays -gt 365) {
                        $status = "CRITICAL"
                    }
                    elseif ($passwordAgeDays -gt 180) {
                        $status = "WARNING"
                    }

                    $rodcInfo = @{
                        Name             = $rodcKrbtgt.SamAccountName
                        DN               = $rodcKrbtgt.DistinguishedName
                        Enabled          = $rodcKrbtgt.Enabled
                        PasswordLastSet  = $pwdLastSet
                        PasswordAgeDays  = $passwordAgeDays
                        EncryptionValue  = $encValue
                        EncryptionTypes  = $encTypes
                        Status           = $status
                    }
                    $assessment.RODCKrbtgtAccounts += $rodcInfo

                    # Report findings per RODC KRBTGT
                    $pwdDateStr = if ($pwdLastSet) { $pwdLastSet.ToString('yyyy-MM-dd') } else { 'Unknown' }
                    if ($status -eq "CRITICAL") {
                        Write-Finding -Status "CRITICAL" -Message "$($rodcKrbtgt.SamAccountName) password is $passwordAgeDays days old (last set: $pwdDateStr)" `
                            -Detail "RODC KRBTGT passwords should be rotated at least every 180 days"
                    }
                    elseif ($status -eq "WARNING") {
                        Write-Finding -Status "WARNING" -Message "$($rodcKrbtgt.SamAccountName) password is $passwordAgeDays days old (last set: $pwdDateStr)"
                    }
                    else {
                        Write-Finding -Status "OK" -Message "$($rodcKrbtgt.SamAccountName) password age: $passwordAgeDays days (last set: $pwdDateStr)"
                    }

                    # Check encryption types
                    if ($encValue -and ($encValue -band 0x4) -and -not ($encValue -band 0x18)) {
                        Write-Finding -Status "CRITICAL" -Message "$($rodcKrbtgt.SamAccountName) has RC4-only encryption configured" `
                            -Detail "Encryption types: $encTypes (Value: 0x$($encValue.ToString('X')))"
                    }
                }
            }
            else {
                Write-Finding -Status "INFO" -Message "No RODC KRBTGT accounts found (no RODCs in this domain)"
            }
        }
        catch {
            Write-Finding -Status "WARNING" -Message "Could not query RODC KRBTGT accounts: $($_.Exception.Message)"
        }

        # ────────────────────────────────────────────────
        # 2. Accounts with USE_DES_KEY_ONLY flag
        # ────────────────────────────────────────────────
        Write-Host "`n  Checking for accounts with USE_DES_KEY_ONLY flag..." -ForegroundColor Cyan

        try {
            # UAC bit 0x200000 = 2097152 = USE_DES_KEY_ONLY
            $desAccounts = Get-ADUser -Filter 'UserAccountControl -band 2097152' `
                -Properties UserAccountControl, 'msDS-SupportedEncryptionTypes', PasswordLastSet, ServicePrincipalName, Enabled, lastLogonTimestamp @ServerParams -ErrorAction Stop

            if ($desAccounts) {
                $desList = @($desAccounts)
                $assessment.TotalDESFlag = $desList.Count

                foreach ($acct in $desList) {
                    $logon = ConvertFrom-LastLogonTimestamp -RawValue $acct.lastLogonTimestamp
                    $acctInfo = @{
                        Name             = $acct.SamAccountName
                        DN               = $acct.DistinguishedName
                        Enabled          = $acct.Enabled
                        PasswordLastSet  = $acct.PasswordLastSet
                        EncryptionValue  = $acct.'msDS-SupportedEncryptionTypes'
                        EncryptionTypes  = Get-EncryptionTypeString -Value $acct.'msDS-SupportedEncryptionTypes'
                        HasSPN           = [bool]$acct.ServicePrincipalName
                        LastLogon        = $logon.LastLogon
                        LastLogonDaysAgo = $logon.LastLogonDaysAgo
                        Flag             = "USE_DES_KEY_ONLY"
                    }
                    $assessment.DESFlagAccounts += $acctInfo
                }

                Write-Finding -Status "CRITICAL" -Message "$($desList.Count) account(s) have USE_DES_KEY_ONLY flag set in UserAccountControl" `
                    -Detail "These accounts are forced to use DES encryption - immediate remediation required"

                foreach ($acct in $assessment.DESFlagAccounts) {
                    $enabledStr = if ($acct.Enabled) { "Enabled" } else { "Disabled" }
                    $logonStr = if ($acct.LastLogon) { ", Last logon: $($acct.LastLogon.ToString('yyyy-MM-dd'))" } else { ", Last logon: Never" }
                    Write-Host "    $([char]0x2022) $($acct.Name) ($enabledStr)$logonStr" -ForegroundColor Red
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
                -Properties ServicePrincipalName, 'msDS-SupportedEncryptionTypes', PasswordLastSet, Enabled, DisplayName, lastLogonTimestamp @ServerParams -ErrorAction Stop

            if ($svcAccounts) {
                $svcList = @($svcAccounts)
                Write-Finding -Status "INFO" -Message "Found $($svcList.Count) service account(s) with SPNs"

                foreach ($svc in $svcList) {
                    $encValue = $svc.'msDS-SupportedEncryptionTypes'
                    $pwdAge = if ($svc.PasswordLastSet) { ((Get-Date) - $svc.PasswordLastSet).Days } else { -1 }
                    $logon = ConvertFrom-LastLogonTimestamp -RawValue $svc.lastLogonTimestamp

                    # Check for RC4-only (has RC4 bit but no AES bits)
                    if ($encValue -and ($encValue -band 0x4) -and -not ($encValue -band 0x18)) {
                        $svcInfo = @{
                            Name             = $svc.SamAccountName
                            DN               = $svc.DistinguishedName
                            Enabled          = $svc.Enabled
                            PasswordLastSet  = $svc.PasswordLastSet
                            PasswordAgeDays  = $pwdAge
                            EncryptionValue  = $encValue
                            EncryptionTypes  = Get-EncryptionTypeString -Value $encValue
                            SPNs             = ($svc.ServicePrincipalName | Select-Object -First 3) -join "; "
                            LastLogon        = $logon.LastLogon
                            LastLogonDaysAgo = $logon.LastLogonDaysAgo
                            Type             = "RC4-Only Service Account"
                        }
                        $assessment.RC4OnlyServiceAccounts += $svcInfo
                    }

                    # Check for DES-only (has DES bits but no AES bits)
                    if ($encValue -and ($encValue -band 0x3) -and -not ($encValue -band 0x18)) {
                        $svcInfo = @{
                            Name             = $svc.SamAccountName
                            DN               = $svc.DistinguishedName
                            Enabled          = $svc.Enabled
                            PasswordLastSet  = $svc.PasswordLastSet
                            PasswordAgeDays  = $pwdAge
                            EncryptionValue  = $encValue
                            EncryptionTypes  = Get-EncryptionTypeString -Value $encValue
                            SPNs             = ($svc.ServicePrincipalName | Select-Object -First 3) -join "; "
                            LastLogon        = $logon.LastLogon
                            LastLogonDaysAgo = $logon.LastLogonDaysAgo
                            Type             = "DES-Only Service Account"
                        }
                        # Avoid duplicate if already caught by RC4 check (e.g., value 0x7 = DES+RC4)
                        if ($svc.SamAccountName -notin $assessment.RC4OnlyServiceAccounts.Name) {
                            $assessment.RC4OnlyServiceAccounts += $svcInfo
                        }
                    }

                    # Check for DES bits enabled (has DES bits, even alongside AES - DES is removed in Server 2025)
                    if ($encValue -and ($encValue -band 0x3) -and ($encValue -band 0x18)) {
                        $desInfo = @{
                            Name             = $svc.SamAccountName
                            DN               = $svc.DistinguishedName
                            Enabled          = $svc.Enabled
                            PasswordLastSet  = $svc.PasswordLastSet
                            PasswordAgeDays  = $pwdAge
                            EncryptionValue  = $encValue
                            EncryptionTypes  = Get-EncryptionTypeString -Value $encValue
                            SPNs             = ($svc.ServicePrincipalName | Select-Object -First 3) -join "; "
                            LastLogon        = $logon.LastLogon
                            LastLogonDaysAgo = $logon.LastLogonDaysAgo
                            AccountType      = "Service Account (SPN)"
                        }
                        if ($svc.SamAccountName -notin $assessment.DESEnabledAccounts.Name) {
                            $assessment.DESEnabledAccounts += $desInfo
                        }
                    }

                    # Check for explicit RC4 exception (has RC4 + AES = 0x1C or similar)
                    if ($encValue -and ($encValue -band 0x4) -and ($encValue -band 0x18)) {
                        $excInfo = @{
                            Name             = $svc.SamAccountName
                            DN               = $svc.DistinguishedName
                            Enabled          = $svc.Enabled
                            PasswordLastSet  = $svc.PasswordLastSet
                            PasswordAgeDays  = $pwdAge
                            EncryptionValue  = $encValue
                            EncryptionTypes  = Get-EncryptionTypeString -Value $encValue
                            SPNs             = ($svc.ServicePrincipalName | Select-Object -First 3) -join "; "
                            LastLogon        = $logon.LastLogon
                            LastLogonDaysAgo = $logon.LastLogonDaysAgo
                            AccountType      = "Service Account (SPN)"
                        }
                        if ($svc.SamAccountName -notin $assessment.RC4ExceptionAccounts.Name) {
                            $assessment.RC4ExceptionAccounts += $excInfo
                        }
                    }

                    # Check for stale password with RC4 enabled (>365 days old, RC4 bit set, account enabled)
                    if ($pwdAge -gt 365 -and $encValue -and ($encValue -band 0x4) -and $svc.Enabled) {
                        $svcInfo = @{
                            Name             = $svc.SamAccountName
                            DN               = $svc.DistinguishedName
                            Enabled          = $svc.Enabled
                            PasswordLastSet  = $svc.PasswordLastSet
                            PasswordAgeDays  = $pwdAge
                            EncryptionValue  = $encValue
                            EncryptionTypes  = Get-EncryptionTypeString -Value $encValue
                            SPNs             = ($svc.ServicePrincipalName | Select-Object -First 3) -join "; "
                            LastLogon        = $logon.LastLogon
                            LastLogonDaysAgo = $logon.LastLogonDaysAgo
                            Type             = "Stale Password Service Account"
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
                        $logonStr = if ($svc.LastLogon) { ", Last logon: $($svc.LastLogon.ToString('yyyy-MM-dd'))" } else { ", Last logon: Never" }
                        Write-Host "    $([char]0x2022) $($svc.Name) ($enabledStr) - $($svc.EncryptionTypes)$logonStr" -ForegroundColor Red
                        Write-Host "      SPNs: $($svc.SPNs)" -ForegroundColor Gray
                    }
                }
                else {
                    Write-Finding -Status "OK" -Message "No service accounts have RC4/DES-only encryption configured"
                }

                if ($assessment.StaleServiceAccounts.Count -gt 0) {
                    Write-Finding -Status "WARNING" -Message "$($assessment.StaleServiceAccounts.Count) service account(s) have stale passwords (>365 days) with RC4 enabled"
                    foreach ($svc in $assessment.StaleServiceAccounts) {
                        $logonStr = if ($svc.LastLogon) { ", Last logon: $($svc.LastLogon.ToString('yyyy-MM-dd'))" } else { ", Last logon: Never" }
                        Write-Host "    $([char]0x2022) $($svc.Name) - Password age: $($svc.PasswordAgeDays) days, Types: $($svc.EncryptionTypes)$logonStr" -ForegroundColor Yellow
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
        # 4. Managed Service Accounts (gMSA/sMSA/dMSA)
        # ────────────────────────────────────────────────
        Write-Host "`n  Checking Managed Service Accounts (gMSA/sMSA/dMSA)..." -ForegroundColor Cyan

        try {
            $msaAccounts = Get-ADServiceAccount -Filter * `
                -Properties 'msDS-SupportedEncryptionTypes', PasswordLastSet, Enabled, ServicePrincipalName, ObjectClass, lastLogonTimestamp @ServerParams -ErrorAction Stop

            if ($msaAccounts) {
                $msaList = @($msaAccounts)
                Write-Finding -Status "INFO" -Message "Found $($msaList.Count) Managed Service Account(s)"

                foreach ($msa in $msaList) {
                    $encValue = $msa.'msDS-SupportedEncryptionTypes'
                    $logon = ConvertFrom-LastLogonTimestamp -RawValue $msa.lastLogonTimestamp

                    # Check for RC4-only (has RC4 bit but no AES bits)
                    if ($encValue -and ($encValue -band 0x4) -and -not ($encValue -band 0x18)) {
                        $msaInfo = @{
                            Name             = $msa.SamAccountName
                            DN               = $msa.DistinguishedName
                            Enabled          = $msa.Enabled
                            PasswordLastSet  = $msa.PasswordLastSet
                            EncryptionValue  = $encValue
                            EncryptionTypes  = Get-EncryptionTypeString -Value $encValue
                            ObjectClass      = $msa.ObjectClass
                            LastLogon        = $logon.LastLogon
                            LastLogonDaysAgo = $logon.LastLogonDaysAgo
                            Type             = switch ($msa.ObjectClass) { 'msDS-GroupManagedServiceAccount' { 'gMSA' } 'msDS-DelegatedManagedServiceAccount' { 'dMSA' } default { 'sMSA' } }
                        }
                        $assessment.RC4OnlyMSAs += $msaInfo
                    }

                    # Check for explicit RC4 exception on MSA (has RC4 + AES = 0x1C or similar)
                    if ($encValue -and ($encValue -band 0x4) -and ($encValue -band 0x18)) {
                        $excInfo = @{
                            Name             = $msa.SamAccountName
                            DN               = $msa.DistinguishedName
                            Enabled          = $msa.Enabled
                            PasswordLastSet  = $msa.PasswordLastSet
                            EncryptionValue  = $encValue
                            EncryptionTypes  = Get-EncryptionTypeString -Value $encValue
                            LastLogon        = $logon.LastLogon
                            LastLogonDaysAgo = $logon.LastLogonDaysAgo
                            AccountType      = switch ($msa.ObjectClass) { 'msDS-GroupManagedServiceAccount' { 'gMSA' } 'msDS-DelegatedManagedServiceAccount' { 'dMSA' } default { 'sMSA' } }
                        }
                        if ($msa.SamAccountName -notin $assessment.RC4ExceptionAccounts.Name) {
                            $assessment.RC4ExceptionAccounts += $excInfo
                        }
                    }

                    # Check for DES bits enabled on MSA (has DES bits, even alongside AES)
                    if ($encValue -and ($encValue -band 0x3) -and ($encValue -band 0x18)) {
                        $desInfo = @{
                            Name             = $msa.SamAccountName
                            DN               = $msa.DistinguishedName
                            Enabled          = $msa.Enabled
                            PasswordLastSet  = $msa.PasswordLastSet
                            EncryptionValue  = $encValue
                            EncryptionTypes  = Get-EncryptionTypeString -Value $encValue
                            LastLogon        = $logon.LastLogon
                            LastLogonDaysAgo = $logon.LastLogonDaysAgo
                            AccountType      = switch ($msa.ObjectClass) { 'msDS-GroupManagedServiceAccount' { 'gMSA' } 'msDS-DelegatedManagedServiceAccount' { 'dMSA' } default { 'sMSA' } }
                        }
                        if ($msa.SamAccountName -notin $assessment.DESEnabledAccounts.Name) {
                            $assessment.DESEnabledAccounts += $desInfo
                        }
                    }
                }

                $assessment.TotalRC4OnlyMSA = $assessment.RC4OnlyMSAs.Count

                if ($assessment.RC4OnlyMSAs.Count -gt 0) {
                    Write-Finding -Status "WARNING" -Message "$($assessment.RC4OnlyMSAs.Count) Managed Service Account(s) have RC4-only encryption"
                    foreach ($msa in $assessment.RC4OnlyMSAs) {
                        $logonStr = if ($msa.LastLogon) { ", Last logon: $($msa.LastLogon.ToString('yyyy-MM-dd'))" } else { ", Last logon: Never" }
                        Write-Host "    $([char]0x2022) $($msa.Name) ($($msa.Type)) - $($msa.EncryptionTypes)$logonStr" -ForegroundColor Yellow
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

        # Update DES-enabled totals and display
        $assessment.TotalDESEnabled = $assessment.DESEnabledAccounts.Count
        if ($assessment.TotalDESEnabled -gt 0) {
            Write-Finding -Status "WARNING" -Message "$($assessment.TotalDESEnabled) account(s) have DES encryption bits enabled (DES is removed in Server 2025)"
            foreach ($des in $assessment.DESEnabledAccounts) {
                $logonStr = if ($des.LastLogon) { ", Last logon: $($des.LastLogon.ToString('yyyy-MM-dd'))" } else { ", Last logon: Never" }
                Write-Host "    $([char]0x2022) $($des.Name) ($($des.AccountType)) - $($des.EncryptionTypes)$logonStr" -ForegroundColor Yellow
            }
        }

        # Update RC4 exception totals and display
        $assessment.TotalRC4Exception = $assessment.RC4ExceptionAccounts.Count
        if ($assessment.TotalRC4Exception -gt 0) {
            Write-Finding -Status "WARNING" -Message "$($assessment.TotalRC4Exception) account(s) have explicit RC4 exception (RC4 + AES) - review and remove RC4 when possible"
            foreach ($exc in $assessment.RC4ExceptionAccounts) {
                $excType = if ($exc.AccountType) { $exc.AccountType } else { 'Service Account' }
                $logonStr = if ($exc.LastLogon) { ", Last logon: $($exc.LastLogon.ToString('yyyy-MM-dd'))" } else { ", Last logon: Never" }
                Write-Host "    $([char]0x2022) $($exc.Name) ($excType) - $($exc.EncryptionTypes)$logonStr" -ForegroundColor Yellow
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
                # Determine AES threshold date dynamically:
                # The "Read-only Domain Controllers" group is created when DFL is raised to 2008+.
                # Its Created date is the authoritative proxy for when AES key generation became
                # available in this domain. Accounts whose password was last set before this date
                # may lack AES keys.
                $aesThresholdDate = $null
                try {
                    $rodcGroup = Get-ADGroup 'Read-only Domain Controllers' -Properties Created @ServerParams -ErrorAction SilentlyContinue
                    if ($rodcGroup -and $rodcGroup.Created) {
                        $aesThresholdDate = $rodcGroup.Created
                        Write-Finding -Status "INFO" -Message "AES threshold date: $($aesThresholdDate.ToString('yyyy-MM-dd')) (DFL 2008 upgrade detected via RODC group creation)"
                    }
                }
                catch {
                    Write-Verbose "Could not query Read-only Domain Controllers group: $($_.Exception.Message)"
                }

                if (-not $aesThresholdDate) {
                    # Fallback: Windows Server 2008 GA date — conservative lower bound
                    $aesThresholdDate = [DateTime]::new(2008, 2, 27)
                    Write-Finding -Status "INFO" -Message "AES threshold date: $($aesThresholdDate.ToString('yyyy-MM-dd')) (fallback — RODC group not found, using Server 2008 GA date)"
                }

                $aesThresholdAgeDays = ((Get-Date) - $aesThresholdDate).Days

                # Two detection paths for accounts missing AES keys:
                #
                # Path A: msDS-SupportedEncryptionTypes is explicitly set to a non-zero value WITHOUT AES bits
                #         (e.g., 0x4 = RC4-only, 0x3 = DES-only). These accounts genuinely lack AES support
                #         regardless of password age. Already flagged by RC4-only/DES-only checks but also
                #         belong in the Missing AES Keys category for completeness.
                #
                # Path B: msDS-SupportedEncryptionTypes is not set (null/0) AND password predates the AES
                #         threshold (DFL 2008 upgrade). When not set, the account uses domain defaults —
                #         AES keys are generated at password change time if DFL >= 2008. Only flag if the
                #         password was last set before the DFL was raised.

                $missingAESAccounts = @()

                # Path A: Explicit non-AES values — query for accounts with msDS-SupportedEncryptionTypes
                # set but without AES bits (bit 0x18). These definitively lack AES support.
                $explicitNonAES = Get-ADUser -LDAPFilter '(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(msDS-SupportedEncryptionTypes=*))' `
                    -Properties 'msDS-SupportedEncryptionTypes', PasswordLastSet, ServicePrincipalName, WhenCreated, lastLogonTimestamp @ServerParams -ErrorAction Stop

                if ($explicitNonAES) {
                    foreach ($acct in @($explicitNonAES)) {
                        $encValue = $acct.'msDS-SupportedEncryptionTypes'
                        # Skip accounts that have AES bits set — they DO have AES support
                        if ($encValue -and $encValue -ne 0 -and -not ($encValue -band 0x18)) {
                            $pwdAge = if ($acct.PasswordLastSet) { ((Get-Date) - $acct.PasswordLastSet).Days } else { -1 }
                            $logon = ConvertFrom-LastLogonTimestamp -RawValue $acct.lastLogonTimestamp
                            $missingAESAccounts += @{
                                Name             = $acct.SamAccountName
                                DN               = $acct.DistinguishedName
                                PasswordLastSet  = $acct.PasswordLastSet
                                PasswordAgeDays  = $pwdAge
                                WhenCreated      = $acct.WhenCreated
                                HasSPN           = [bool]$acct.ServicePrincipalName
                                EncryptionValue  = $encValue
                                EncryptionTypes  = Get-EncryptionTypeString -Value $encValue
                                LastLogon        = $logon.LastLogon
                                LastLogonDaysAgo = $logon.LastLogonDaysAgo
                                Type             = "Missing AES Keys (explicit non-AES)"
                            }
                        }
                    }
                }

                # Path B: Attribute not set + password predates AES threshold (DFL 2008 upgrade)
                $oldAccounts = Get-ADUser -Filter { Enabled -eq $true -and PasswordLastSet -lt $aesThresholdDate } `
                    -Properties 'msDS-SupportedEncryptionTypes', PasswordLastSet, ServicePrincipalName, WhenCreated, lastLogonTimestamp @ServerParams -ErrorAction Stop

                if ($oldAccounts) {
                    foreach ($acct in @($oldAccounts)) {
                        $encValue = $acct.'msDS-SupportedEncryptionTypes'
                        $pwdAge = if ($acct.PasswordLastSet) { ((Get-Date) - $acct.PasswordLastSet).Days } else { -1 }

                        # Only flag if msDS-SupportedEncryptionTypes is not set (null/0)
                        # AND password predates AES threshold — set before DFL 2008 upgrade
                        if ((-not $encValue -or $encValue -eq 0) -and $pwdAge -gt $aesThresholdAgeDays) {
                            # Skip if already added by Path A
                            if ($acct.SamAccountName -notin $missingAESAccounts.Name) {
                                $logon = ConvertFrom-LastLogonTimestamp -RawValue $acct.lastLogonTimestamp
                                $missingAESAccounts += @{
                                    Name             = $acct.SamAccountName
                                    DN               = $acct.DistinguishedName
                                    PasswordLastSet  = $acct.PasswordLastSet
                                    PasswordAgeDays  = $pwdAge
                                    WhenCreated      = $acct.WhenCreated
                                    HasSPN           = [bool]$acct.ServicePrincipalName
                                    EncryptionValue  = $encValue
                                    EncryptionTypes  = 'Not Set (domain defaults)'
                                    LastLogon        = $logon.LastLogon
                                    LastLogonDaysAgo = $logon.LastLogonDaysAgo
                                    Type             = "Missing AES Keys (attribute not set, old password)"
                                }
                            }
                        }
                    }
                }

                $assessment.MissingAESKeyAccounts = $missingAESAccounts
                $assessment.TotalMissingAES = $missingAESAccounts.Count

                if ($missingAESAccounts.Count -gt 0) {
                    Write-Finding -Status "WARNING" -Message "$($missingAESAccounts.Count) account(s) may be missing AES keys" `
                        -Detail "Reset password for these accounts to generate AES keys"

                    $displayCount = [Math]::Min($missingAESAccounts.Count, 10)
                    foreach ($acct in $missingAESAccounts | Select-Object -First $displayCount) {
                        $spnStr = if ($acct.HasSPN) { " [HAS SPN]" } else { "" }
                        $encStr = if ($acct.EncryptionTypes) { " ($($acct.EncryptionTypes))" } else { "" }
                        $logonStr = if ($acct.LastLogon) { ", Last logon: $($acct.LastLogon.ToString('yyyy-MM-dd')) ($($acct.LastLogonDaysAgo)d ago)" } else { ", Last logon: Never" }
                        Write-Host "    $([char]0x2022) $($acct.Name) - Password age: $($acct.PasswordAgeDays) days$encStr$logonStr$spnStr" -ForegroundColor Yellow
                    }
                    if ($missingAESAccounts.Count -gt 10) {
                        Write-Host "    ... and $($missingAESAccounts.Count - 10) more" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Finding -Status "OK" -Message "No accounts found with potentially missing AES keys"
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
        # 6. DeepScan: All enabled user accounts (non-SPN)
        # ────────────────────────────────────────────────
        if ($DeepScan) {
            Write-Host "`n  [DeepScan] Checking all enabled user accounts (without SPNs)..." -ForegroundColor Cyan

            try {
                # Get enabled users with msDS-SupportedEncryptionTypes set, excluding SPN-bearing accounts (already covered)
                $deepUsers = Get-ADUser -LDAPFilter '(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(msDS-SupportedEncryptionTypes=*)(!(servicePrincipalName=*)))' `
                    -Properties 'msDS-SupportedEncryptionTypes', PasswordLastSet, Enabled, DisplayName, lastLogonTimestamp @ServerParams -ErrorAction Stop

                if ($deepUsers) {
                    $deepUserList = @($deepUsers) | Where-Object { $_.SamAccountName -ne 'krbtgt' }
                    Write-Finding -Status "INFO" -Message "[DeepScan] Evaluating $($deepUserList.Count) enabled user account(s) with explicit encryption types (no SPNs)"

                    foreach ($user in $deepUserList) {
                        $encValue = $user.'msDS-SupportedEncryptionTypes'
                        $logon = ConvertFrom-LastLogonTimestamp -RawValue $user.lastLogonTimestamp

                        $userInfo = @{
                            Name             = $user.SamAccountName
                            DN               = $user.DistinguishedName
                            Enabled          = $user.Enabled
                            PasswordLastSet  = $user.PasswordLastSet
                            EncryptionValue  = $encValue
                            EncryptionTypes  = Get-EncryptionTypeString -Value $encValue
                            LastLogon        = $logon.LastLogon
                            LastLogonDaysAgo = $logon.LastLogonDaysAgo
                            AccountType      = "User Account (no SPN)"
                        }

                        # RC4-only: has RC4 but no AES (includes DES+RC4 combos without AES)
                        if ($encValue -band 0x4 -and -not ($encValue -band 0x18)) {
                            $assessment.DeepScanRC4OnlyUsers += $userInfo
                        }

                        # DES-only: has DES but no RC4 and no AES
                        if ($encValue -band 0x3 -and -not ($encValue -band 0x4) -and -not ($encValue -band 0x18)) {
                            $assessment.DeepScanDESOnlyUsers += $userInfo
                        }

                        # DES-enabled: DES bits alongside AES
                        if ($encValue -band 0x3 -and ($encValue -band 0x18)) {
                            $assessment.DeepScanDESEnabledUsers += $userInfo
                        }

                        # RC4 exception: RC4 alongside AES
                        if ($encValue -band 0x4 -and ($encValue -band 0x18)) {
                            $assessment.DeepScanRC4ExceptionUsers += $userInfo
                        }
                    }

                    # Update totals
                    $assessment.TotalDeepScanRC4OnlyUsers = $assessment.DeepScanRC4OnlyUsers.Count
                    $assessment.TotalDeepScanDESOnlyUsers = $assessment.DeepScanDESOnlyUsers.Count
                    $assessment.TotalDeepScanDESEnabledUsers = $assessment.DeepScanDESEnabledUsers.Count
                    $assessment.TotalDeepScanRC4ExceptionUsers = $assessment.DeepScanRC4ExceptionUsers.Count

                    # Display findings
                    if ($assessment.DeepScanRC4OnlyUsers.Count -gt 0) {
                        Write-Finding -Status "CRITICAL" -Message "[DeepScan] $($assessment.DeepScanRC4OnlyUsers.Count) user account(s) have RC4-only encryption configured"
                        foreach ($u in $assessment.DeepScanRC4OnlyUsers) {
                            $logonStr = if ($u.LastLogon) { ", Last logon: $($u.LastLogon.ToString('yyyy-MM-dd'))" } else { ", Last logon: Never" }
                            Write-Host "    $([char]0x2022) $($u.Name) - $($u.EncryptionTypes)$logonStr" -ForegroundColor Red
                        }
                    }

                    if ($assessment.DeepScanDESOnlyUsers.Count -gt 0) {
                        Write-Finding -Status "CRITICAL" -Message "[DeepScan] $($assessment.DeepScanDESOnlyUsers.Count) user account(s) have DES-only encryption configured"
                        foreach ($u in $assessment.DeepScanDESOnlyUsers) {
                            $logonStr = if ($u.LastLogon) { ", Last logon: $($u.LastLogon.ToString('yyyy-MM-dd'))" } else { ", Last logon: Never" }
                            Write-Host "    $([char]0x2022) $($u.Name) - $($u.EncryptionTypes)$logonStr" -ForegroundColor Red
                        }
                    }

                    if ($assessment.DeepScanDESEnabledUsers.Count -gt 0) {
                        Write-Finding -Status "WARNING" -Message "[DeepScan] $($assessment.DeepScanDESEnabledUsers.Count) user account(s) have DES encryption bits enabled alongside AES"
                        foreach ($u in $assessment.DeepScanDESEnabledUsers) {
                            $logonStr = if ($u.LastLogon) { ", Last logon: $($u.LastLogon.ToString('yyyy-MM-dd'))" } else { ", Last logon: Never" }
                            Write-Host "    $([char]0x2022) $($u.Name) - $($u.EncryptionTypes)$logonStr" -ForegroundColor Yellow
                        }
                    }

                    if ($assessment.DeepScanRC4ExceptionUsers.Count -gt 0) {
                        Write-Finding -Status "WARNING" -Message "[DeepScan] $($assessment.DeepScanRC4ExceptionUsers.Count) user account(s) have explicit RC4 exception (RC4 + AES)"
                        foreach ($u in $assessment.DeepScanRC4ExceptionUsers) {
                            $logonStr = if ($u.LastLogon) { ", Last logon: $($u.LastLogon.ToString('yyyy-MM-dd'))" } else { ", Last logon: Never" }
                            Write-Host "    $([char]0x2022) $($u.Name) - $($u.EncryptionTypes)$logonStr" -ForegroundColor Yellow
                        }
                    }

                    if ($assessment.DeepScanRC4OnlyUsers.Count -eq 0 -and $assessment.DeepScanDESOnlyUsers.Count -eq 0 -and
                        $assessment.DeepScanDESEnabledUsers.Count -eq 0 -and $assessment.DeepScanRC4ExceptionUsers.Count -eq 0) {
                        Write-Finding -Status "OK" -Message "[DeepScan] No user accounts (without SPNs) have problematic encryption configurations"
                    }
                }
                else {
                    Write-Finding -Status "OK" -Message "[DeepScan] No enabled user accounts found with explicit encryption types set"
                }
            }
            catch {
                Write-Finding -Status "WARNING" -Message "[DeepScan] Could not query user accounts: $($_.Exception.Message)"
            }

            # ────────────────────────────────────────────────
            # 7. DeepScan: Computer accounts (excluding DCs)
            # ────────────────────────────────────────────────
            Write-Host "`n  [DeepScan] Checking enabled computer accounts (excluding DCs)..." -ForegroundColor Cyan

            try {
                # Get enabled computers with msDS-SupportedEncryptionTypes set, excluding DCs (PrimaryGroupID 516)
                $deepComputers = Get-ADComputer -LDAPFilter '(&(!(primaryGroupID=516))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(msDS-SupportedEncryptionTypes=*))' `
                    -Properties 'msDS-SupportedEncryptionTypes', OperatingSystem, PasswordLastSet, lastLogonTimestamp @ServerParams -ErrorAction Stop

                if ($deepComputers) {
                    $computerList = @($deepComputers)
                    Write-Finding -Status "INFO" -Message "[DeepScan] Evaluating $($computerList.Count) enabled computer account(s) with explicit encryption types"

                    foreach ($comp in $computerList) {
                        $encValue = $comp.'msDS-SupportedEncryptionTypes'

                        # Skip AES-only (0x18) — already secure
                        if ($encValue -eq 0x18) { continue }

                        # OS-default: Windows stamps 0x1C (RC4+AES128+AES256) on domain join
                        if ($encValue -eq 0x1C) {
                            $assessment.DeepScanComputersOSDefault++
                            continue
                        }

                        # Any other value with RC4 or DES bits is problematic
                        if ($encValue -band 0x7) {
                            $logon = ConvertFrom-LastLogonTimestamp -RawValue $comp.lastLogonTimestamp
                            $compInfo = @{
                                Name             = $comp.SamAccountName -replace '\$$'
                                DN               = $comp.DistinguishedName
                                OperatingSystem  = $comp.OperatingSystem
                                PasswordLastSet  = $comp.PasswordLastSet
                                EncryptionValue  = $encValue
                                EncryptionTypes  = Get-EncryptionTypeString -Value $encValue
                                LastLogon        = $logon.LastLogon
                                LastLogonDaysAgo = $logon.LastLogonDaysAgo
                            }
                            $assessment.DeepScanComputersProblematic += $compInfo
                        }
                    }

                    $assessment.TotalDeepScanComputersProblematic = $assessment.DeepScanComputersProblematic.Count

                    # Report OS-default computers (INFO — fix with a single GPO)
                    if ($assessment.DeepScanComputersOSDefault -gt 0) {
                        Write-Finding -Status "INFO" -Message "[DeepScan] $($assessment.DeepScanComputersOSDefault) computer(s) have OS-default encryption (0x1C = RC4+AES)" `
                            -Detail "Windows stamps RC4+AES on domain join. Deploy a domain-level GPO to set 'Network security: Configure encryption types allowed for Kerberos' = AES128 + AES256 + Future encryption types"
                    }

                    # Report problematic computers (WARNING — need per-computer investigation)
                    if ($assessment.DeepScanComputersProblematic.Count -gt 0) {
                        Write-Finding -Status "WARNING" -Message "[DeepScan] $($assessment.DeepScanComputersProblematic.Count) computer(s) have non-default RC4/DES encryption types"
                        foreach ($c in $assessment.DeepScanComputersProblematic) {
                            $logonStr = if ($c.LastLogon) { ", Last logon: $($c.LastLogon.ToString('yyyy-MM-dd'))" } else { ", Last logon: Never" }
                            $osStr = if ($c.OperatingSystem) { " [$($c.OperatingSystem)]" } else { "" }
                            Write-Host "    $([char]0x2022) $($c.Name)$osStr - $($c.EncryptionTypes) (0x$($c.EncryptionValue.ToString('X')))$logonStr" -ForegroundColor Yellow
                        }
                    }

                    if ($assessment.DeepScanComputersOSDefault -eq 0 -and $assessment.DeepScanComputersProblematic.Count -eq 0) {
                        Write-Finding -Status "OK" -Message "[DeepScan] No computer accounts have problematic encryption configurations"
                    }
                }
                else {
                    Write-Finding -Status "OK" -Message "[DeepScan] No computer accounts found with explicit encryption types set"
                }
            }
            catch {
                Write-Finding -Status "WARNING" -Message "[DeepScan] Could not query computer accounts: $($_.Exception.Message)"
            }
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
        Write-Host "  $([char]0x2022) DES-Enabled Accounts (insecure): $($assessment.TotalDESEnabled)" -ForegroundColor $(if ($assessment.TotalDESEnabled -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  $([char]0x2022) RC4 Exception Accounts (RC4+AES): $($assessment.TotalRC4Exception)" -ForegroundColor $(if ($assessment.TotalRC4Exception -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  $([char]0x2022) Stale Password Service Accounts (>365d, RC4): $($assessment.TotalStaleSvc)" -ForegroundColor $(if ($assessment.TotalStaleSvc -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  $([char]0x2022) Accounts Missing AES Keys: $($assessment.TotalMissingAES)" -ForegroundColor $(if ($assessment.TotalMissingAES -gt 0) { "Yellow" } else { "Green" })
        if ($DeepScan) {
            Write-Host "  $([char]0x2022) [DeepScan] RC4-Only Users (no SPN): $($assessment.TotalDeepScanRC4OnlyUsers)" -ForegroundColor $(if ($assessment.TotalDeepScanRC4OnlyUsers -gt 0) { "Red" } else { "Green" })
            Write-Host "  $([char]0x2022) [DeepScan] DES-Only Users (no SPN): $($assessment.TotalDeepScanDESOnlyUsers)" -ForegroundColor $(if ($assessment.TotalDeepScanDESOnlyUsers -gt 0) { "Red" } else { "Green" })
            Write-Host "  $([char]0x2022) [DeepScan] DES-Enabled Users (no SPN): $($assessment.TotalDeepScanDESEnabledUsers)" -ForegroundColor $(if ($assessment.TotalDeepScanDESEnabledUsers -gt 0) { "Yellow" } else { "Green" })
            Write-Host "  $([char]0x2022) [DeepScan] RC4 Exception Users (no SPN): $($assessment.TotalDeepScanRC4ExceptionUsers)" -ForegroundColor $(if ($assessment.TotalDeepScanRC4ExceptionUsers -gt 0) { "Yellow" } else { "Green" })
            Write-Host "  $([char]0x2022) [DeepScan] Computers OS-Default (0x1C): $($assessment.DeepScanComputersOSDefault)" -ForegroundColor $(if ($assessment.DeepScanComputersOSDefault -gt 0) { "Cyan" } else { "Green" })
            Write-Host "  $([char]0x2022) [DeepScan] Computers Problematic (non-default): $($assessment.TotalDeepScanComputersProblematic)" -ForegroundColor $(if ($assessment.TotalDeepScanComputersProblematic -gt 0) { "Yellow" } else { "Green" })
        }
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
