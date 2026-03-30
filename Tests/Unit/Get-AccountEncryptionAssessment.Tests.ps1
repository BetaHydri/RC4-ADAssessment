BeforeAll {
    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADUser' -ErrorAction SilentlyContinue)) {
        function global:Get-ADUser { param([string]$Identity, [string]$Filter, [string[]]$Properties, [string]$SearchBase, [string]$Server, $ErrorAction) }
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
}
}
