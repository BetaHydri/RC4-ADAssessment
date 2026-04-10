BeforeAll {
    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADTrust' -ErrorAction SilentlyContinue)) {
        function global:Get-ADTrust { param([string]$Filter, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
}

InModuleScope 'RC4-ADAssessment' {
Describe 'Get-TrustEncryptionAssessment' {
    BeforeEach {
        Mock -ModuleName 'RC4-ADAssessment' Write-Host {}
        Mock -ModuleName 'RC4-ADAssessment' Get-ADDomain {
            [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
        }
    }

    Context 'When no trusts exist' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADTrust { $null }
        }

        It 'Returns zero total trusts' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.TotalTrusts | Should -Be 0
        }
    }

    Context 'When a trust has AES encryption' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADTrust {
                @([PSCustomObject]@{
                    Name = 'partner.com'
                    Direction = 'BiDirectional'
                    TrustDirection = 3
                    TrustType = 'Forest'
                    'msDS-SupportedEncryptionTypes' = 24
                })
            }
        }

        It 'Counts one trust' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.TotalTrusts | Should -Be 1
        }

        It 'Reports no RC4 risk' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.RC4Risk | Should -Be 0
        }

        It 'Includes direction label in details' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.Details[0].Direction | Should -Be '3 (Bidirectional)'
        }
    }

    Context 'When a trust has RC4 only' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADTrust {
                @([PSCustomObject]@{
                    Name = 'legacy.com'
                    Direction = 'Outbound'
                    TrustDirection = 2
                    TrustType = 'External'
                    'msDS-SupportedEncryptionTypes' = 4
                })
            }
        }

        It 'Reports RC4 risk' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.RC4Risk | Should -Be 1
        }

        It 'Includes direction label in details' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.Details[0].Direction | Should -Be '2 (Outbound)'
        }
    }
}
}
