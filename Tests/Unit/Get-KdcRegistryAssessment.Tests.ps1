BeforeAll {
    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADDomainController' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomainController { param([string]$DomainName, [switch]$Discover, [string]$Filter, [string]$Server, $ErrorAction) }
    }
}

InModuleScope 'RC4ADCheck' {
Describe 'Get-KdcRegistryAssessment' {
    BeforeEach {
        Mock -ModuleName 'RC4ADCheck' Write-Host {}
        Mock -ModuleName 'RC4ADCheck' Get-ADDomain {
            [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
        }
    }

    Context 'When no DCs are found' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADDomainController { @() }
        }

        It 'Returns empty QueriedDCs list' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.QueriedDCs.Count | Should -Be 0
        }
    }

    Context 'When DC registry has AES-only DefaultDomainSupportedEncTypes' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' })
            }
            Mock -ModuleName 'RC4ADCheck' Invoke-Command {
                @{ DefaultDomainSupportedEncTypes = 24; RC4DefaultDisablementPhase = 1 }
            }
        }

        It 'Reports DefaultDomainSupportedEncTypes as configured' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.DefaultDomainSupportedEncTypes.Configured | Should -BeTrue
        }

        It 'Reports AES included' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.DefaultDomainSupportedEncTypes.IncludesAES | Should -BeTrue
        }

        It 'Reports RC4 not included' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.DefaultDomainSupportedEncTypes.IncludesRC4 | Should -BeFalse
        }

        It 'Reports RC4DefaultDisablementPhase as configured' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.RC4DefaultDisablementPhase.Configured | Should -BeTrue
        }
    }

    Context 'When Invoke-Command fails' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' })
            }
            Mock -ModuleName 'RC4ADCheck' Invoke-Command { throw 'WinRM error' }
        }

        It 'Adds DC to FailedDCs list' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.FailedDCs.Count | Should -Be 1
        }
    }
}
}
