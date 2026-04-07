BeforeAll {
    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADUser' -ErrorAction SilentlyContinue)) {
        function global:Get-ADUser { param([string]$Identity, [string]$Filter, [string]$LDAPFilter, [string[]]$Properties, [string]$SearchBase, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADComputer' -ErrorAction SilentlyContinue)) {
        function global:Get-ADComputer { param([string]$Identity, [string]$Filter, [string]$LDAPFilter, [string[]]$Properties, [string]$SearchBase, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADServiceAccount' -ErrorAction SilentlyContinue)) {
        function global:Get-ADServiceAccount { param([string]$Identity, [string]$Filter, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
}

InModuleScope 'RC4-ADAssessment' {
Describe 'Get-AccountEncryptionAssessment' {
    BeforeEach {
        Mock -ModuleName 'RC4-ADAssessment' Write-Host {}
        Mock -ModuleName 'RC4-ADAssessment' Get-ADDomain {
            [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
        }
        Mock -ModuleName 'RC4-ADAssessment' Get-ADServiceAccount { $null }
    }

    Context 'When KRBTGT has healthy AES config' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-90)
                        pwdLastSet                      = (Get-Date).AddDays(-90).ToFileTime()
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-90)
                    }
                }
                return $null
            }
        }

        It 'Returns a hashtable with KRBTGT data' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.KRBTGT | Should -Not -BeNullOrEmpty
        }

        It 'Reports KRBTGT password age' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.KRBTGT.PasswordAgeDays | Should -BeGreaterOrEqual 89
        }
    }

    Context 'When no service accounts exist' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = (Get-Date).AddDays(-30).ToFileTime()
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                return $null
            }
        }

        It 'Returns zero RC4-only service accounts' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalRC4OnlySvc | Should -Be 0
        }

        It 'Returns zero DES-flag accounts' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalDESFlag | Should -Be 0
        }
    }

    Context 'When DeepScan is not specified' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = (Get-Date).AddDays(-30).ToFileTime()
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                return $null
            }
        }

        It 'Returns zero DeepScan counters' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalDeepScanRC4OnlyUsers | Should -Be 0
            $result.TotalDeepScanDESOnlyUsers | Should -Be 0
            $result.TotalDeepScanDESEnabledUsers | Should -Be 0
            $result.TotalDeepScanRC4ExceptionUsers | Should -Be 0
            $result.TotalDeepScanComputersProblematic | Should -Be 0
            $result.DeepScanComputersOSDefault | Should -Be 0
        }
    }

    Context 'When DeepScan finds RC4-only user accounts' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = (Get-Date).AddDays(-30).ToFileTime()
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                # LDAPFilter call: neither -Identity nor -Filter is used
                if (-not $Identity -and -not $Filter) {
                    return @(
                        [PSCustomObject]@{
                            SamAccountName                  = 'rc4user'
                            DistinguishedName               = 'CN=rc4user,DC=contoso,DC=com'
                            Enabled                         = $true
                            PasswordLastSet                 = (Get-Date).AddDays(-60)
                            'msDS-SupportedEncryptionTypes' = 4
                            lastLogonTimestamp               = (Get-Date).AddDays(-1).ToFileTime()
                        }
                    )
                }
                return $null
            }
            Mock -ModuleName 'RC4-ADAssessment' Get-ADComputer { $null }
        }

        It 'Detects RC4-only users' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{} -DeepScan
            $result.TotalDeepScanRC4OnlyUsers | Should -Be 1
            $result.DeepScanRC4OnlyUsers[0].Name | Should -Be 'rc4user'
        }
    }

    Context 'When DeepScan finds DES-only user accounts' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = (Get-Date).AddDays(-30).ToFileTime()
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                if (-not $Identity -and -not $Filter) {
                    return @(
                        [PSCustomObject]@{
                            SamAccountName                  = 'desuser'
                            DistinguishedName               = 'CN=desuser,DC=contoso,DC=com'
                            Enabled                         = $true
                            PasswordLastSet                 = (Get-Date).AddDays(-90)
                            'msDS-SupportedEncryptionTypes' = 3
                            lastLogonTimestamp               = $null
                        }
                    )
                }
                return $null
            }
            Mock -ModuleName 'RC4-ADAssessment' Get-ADComputer { $null }
        }

        It 'Detects DES-only users' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{} -DeepScan
            $result.TotalDeepScanDESOnlyUsers | Should -Be 1
            $result.DeepScanDESOnlyUsers[0].Name | Should -Be 'desuser'
        }
    }

    Context 'When DeepScan finds RC4 exception user accounts' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = (Get-Date).AddDays(-30).ToFileTime()
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                if (-not $Identity -and -not $Filter) {
                    return @(
                        [PSCustomObject]@{
                            SamAccountName                  = 'excuser'
                            DistinguishedName               = 'CN=excuser,DC=contoso,DC=com'
                            Enabled                         = $true
                            PasswordLastSet                 = (Get-Date).AddDays(-10)
                            'msDS-SupportedEncryptionTypes' = 0x1C
                            lastLogonTimestamp               = (Get-Date).AddDays(-2).ToFileTime()
                        }
                    )
                }
                return $null
            }
            Mock -ModuleName 'RC4-ADAssessment' Get-ADComputer { $null }
        }

        It 'Detects RC4 exception users' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{} -DeepScan
            $result.TotalDeepScanRC4ExceptionUsers | Should -Be 1
            $result.DeepScanRC4ExceptionUsers[0].Name | Should -Be 'excuser'
        }
    }

    Context 'When DeepScan detects OS-default and problematic computers' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = (Get-Date).AddDays(-30).ToFileTime()
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                return $null
            }
            Mock -ModuleName 'RC4-ADAssessment' Get-ADComputer {
                return @(
                    [PSCustomObject]@{
                        SamAccountName                  = 'WS01$'
                        DistinguishedName               = 'CN=WS01,DC=contoso,DC=com'
                        OperatingSystem                 = 'Windows 11 Enterprise'
                        PasswordLastSet                 = (Get-Date).AddDays(-5)
                        'msDS-SupportedEncryptionTypes' = 0x1C
                        lastLogonTimestamp               = (Get-Date).AddDays(-1).ToFileTime()
                    },
                    [PSCustomObject]@{
                        SamAccountName                  = 'WS02$'
                        DistinguishedName               = 'CN=WS02,DC=contoso,DC=com'
                        OperatingSystem                 = 'Windows 10 Enterprise'
                        PasswordLastSet                 = (Get-Date).AddDays(-10)
                        'msDS-SupportedEncryptionTypes' = 0x1C
                        lastLogonTimestamp               = (Get-Date).AddDays(-2).ToFileTime()
                    },
                    [PSCustomObject]@{
                        SamAccountName                  = 'LEGACY01$'
                        DistinguishedName               = 'CN=LEGACY01,DC=contoso,DC=com'
                        OperatingSystem                 = 'Windows Server 2008 R2'
                        PasswordLastSet                 = (Get-Date).AddDays(-200)
                        'msDS-SupportedEncryptionTypes' = 4
                        lastLogonTimestamp               = (Get-Date).AddDays(-30).ToFileTime()
                    }
                )
            }
        }

        It 'Counts OS-default 0x1C computers as INFO' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{} -DeepScan
            $result.DeepScanComputersOSDefault | Should -Be 2
        }

        It 'Lists problematic computers individually' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{} -DeepScan
            $result.TotalDeepScanComputersProblematic | Should -Be 1
            $result.DeepScanComputersProblematic[0].Name | Should -Be 'LEGACY01'
        }

        It 'Strips trailing $ from computer names' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{} -DeepScan
            $result.DeepScanComputersProblematic[0].Name | Should -Not -Match '\$$'
        }
    }

    Context 'When accounts have explicit non-AES encryption (Missing AES Path A)' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomain {
                [PSCustomObject]@{
                    DNSRoot             = 'contoso.com'
                    DistinguishedName   = 'DC=contoso,DC=com'
                    DomainMode          = 'Windows2016Domain'
                }
            }
            # Default mock: return null for any unmatched Get-ADUser call
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser { $null }
            # KRBTGT identity lookup
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser -ParameterFilter { "$Identity" -eq 'krbtgt' } {
                [PSCustomObject]@{
                    SamAccountName                  = 'krbtgt'
                    PasswordLastSet                 = (Get-Date).AddDays(-30)
                    pwdLastSet                      = (Get-Date).AddDays(-30).ToFileTime()
                    'msDS-SupportedEncryptionTypes' = 24
                    WhenChanged                     = (Get-Date).AddDays(-30)
                }
            }
            # Path A: LDAP filter query for explicit non-AES accounts
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser -ParameterFilter { $LDAPFilter -and $LDAPFilter -match 'msDS-SupportedEncryptionTypes' } {
                @(
                    [PSCustomObject]@{
                        SamAccountName                  = 'rc4onlysvc'
                        DistinguishedName               = 'CN=rc4onlysvc,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-60)
                        'msDS-SupportedEncryptionTypes' = 4
                        ServicePrincipalName            = @('HTTP/app.contoso.com')
                        WhenCreated                     = (Get-Date).AddDays(-365)
                        lastLogonTimestamp               = (Get-Date).AddDays(-1).ToFileTime()
                    }
                )
            }
        }

        It 'Detects accounts with explicit non-AES encryption as Missing AES Keys' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalMissingAES | Should -Be 1
            $result.MissingAESKeyAccounts[0].Name | Should -Be 'rc4onlysvc'
        }

        It 'Includes encryption type info in the result' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.MissingAESKeyAccounts[0].EncryptionValue | Should -Be 4
        }
    }

    Context 'When accounts have unset attribute and very old password (Missing AES Path B)' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomain {
                [PSCustomObject]@{
                    DNSRoot             = 'contoso.com'
                    DistinguishedName   = 'DC=contoso,DC=com'
                    DomainMode          = 'Windows2016Domain'
                }
            }
            # Default mock: return null for any unmatched Get-ADUser call
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser { $null }
            # KRBTGT identity lookup
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser -ParameterFilter { "$Identity" -eq 'krbtgt' } {
                [PSCustomObject]@{
                    SamAccountName                  = 'krbtgt'
                    PasswordLastSet                 = (Get-Date).AddDays(-30)
                    pwdLastSet                      = (Get-Date).AddDays(-30).ToFileTime()
                    'msDS-SupportedEncryptionTypes' = 24
                    WhenChanged                     = (Get-Date).AddDays(-30)
                }
            }
            # Path A: LDAP filter — no explicit non-AES accounts
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser -ParameterFilter { $LDAPFilter -and $LDAPFilter -match 'msDS-SupportedEncryptionTypes' } { $null }
            # Path B: Old password accounts with attribute not set
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser -ParameterFilter { $Filter -and "$Filter" -match 'PasswordLastSet' } {
                @(
                    [PSCustomObject]@{
                        SamAccountName                  = 'olduser'
                        DistinguishedName               = 'CN=olduser,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddYears(-7)
                        'msDS-SupportedEncryptionTypes' = $null
                        ServicePrincipalName            = $null
                        WhenCreated                     = (Get-Date).AddYears(-8)
                        lastLogonTimestamp               = $null
                    }
                )
            }
        }

        It 'Detects accounts with unset attribute and old password as Missing AES Keys' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalMissingAES | Should -Be 1
            $result.MissingAESKeyAccounts[0].Name | Should -Be 'olduser'
        }
    }

    Context 'When accounts have AES in explicit encryption types (should NOT be flagged as Missing AES)' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomain {
                [PSCustomObject]@{
                    DNSRoot             = 'contoso.com'
                    DistinguishedName   = 'DC=contoso,DC=com'
                    DomainMode          = 'Windows2016Domain'
                }
            }
            # Default mock: return null for any unmatched Get-ADUser call
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser { $null }
            # KRBTGT identity lookup
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser -ParameterFilter { "$Identity" -eq 'krbtgt' } {
                [PSCustomObject]@{
                    SamAccountName                  = 'krbtgt'
                    PasswordLastSet                 = (Get-Date).AddDays(-30)
                    pwdLastSet                      = (Get-Date).AddDays(-30).ToFileTime()
                    'msDS-SupportedEncryptionTypes' = 24
                    WhenChanged                     = (Get-Date).AddDays(-30)
                }
            }
            # Path A: account with AES bits set — should be skipped by the filter logic
            Mock -ModuleName 'RC4-ADAssessment' Get-ADUser -ParameterFilter { $LDAPFilter -and $LDAPFilter -match 'msDS-SupportedEncryptionTypes' } {
                @(
                    [PSCustomObject]@{
                        SamAccountName                  = 'aesuser'
                        DistinguishedName               = 'CN=aesuser,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddYears(-7)
                        'msDS-SupportedEncryptionTypes' = 0x1C
                        ServicePrincipalName            = $null
                        WhenCreated                     = (Get-Date).AddYears(-8)
                        lastLogonTimestamp               = (Get-Date).AddDays(-5).ToFileTime()
                    }
                )
            }
        }

        It 'Does NOT flag accounts with AES bits as Missing AES Keys' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalMissingAES | Should -Be 0
        }
    }
}
}
