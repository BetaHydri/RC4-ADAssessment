BeforeAll {
    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADTrust' -ErrorAction SilentlyContinue)) {
        function global:Get-ADTrust { param([string]$Filter, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
}

Describe 'Get-TrustEncryptionAssessment' {
    BeforeEach {
        Mock -ModuleName 'RC4ADCheck' Write-Host {}
        Mock -ModuleName 'RC4ADCheck' Get-ADDomain {
            [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
        }
    }

    Context 'When no trusts exist' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADTrust { $null }
        }

        It 'Returns zero total trusts' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.TotalTrusts | Should -Be 0
        }
    }

    Context 'When a trust has AES encryption' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADTrust {
                @([PSCustomObject]@{
                    Name = 'partner.com'
                    Direction = 'BiDirectional'
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
    }

    Context 'When a trust has RC4 only' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADTrust {
                @([PSCustomObject]@{
                    Name = 'legacy.com'
                    Direction = 'Outbound'
                    TrustType = 'External'
                    'msDS-SupportedEncryptionTypes' = 4
                })
            }
        }

        It 'Reports RC4 risk' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.RC4Risk | Should -Be 1
        }
    }
}
