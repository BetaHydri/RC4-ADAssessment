BeforeAll {
    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADDomainController' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomainController { param([string]$DomainName, [switch]$Discover, [string]$Filter, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADComputer' -ErrorAction SilentlyContinue)) {
        function global:Get-ADComputer { param([string]$Identity, [string[]]$Properties, [string]$Filter, [string]$SearchBase, [string]$Server, $ErrorAction) }
    }
}

InModuleScope 'RC4-ADAssessment' {
Describe 'Get-KdcRegistryAssessment' {
    BeforeEach {
        Mock -ModuleName 'RC4-ADAssessment' Write-Host {}
        Mock -ModuleName 'RC4-ADAssessment' Get-ADDomain {
            [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
        }
    }

    Context 'When no DCs are found' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController { @() }
        }

        It 'Returns empty QueriedDCs list' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.QueriedDCs.Count | Should -Be 0
        }
    }

    Context 'When DC registry has AES-only DefaultDomainSupportedEncTypes' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command {
                @{ DefaultDomainSupportedEncTypes = 24; RC4DefaultDisablementPhase = 1; GPOSupportedEncryptionTypes = $null }
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
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command { throw 'WinRM error' }
        }

        It 'Adds DC to FailedDCs list' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.FailedDCs.Count | Should -Be 1
        }
    }

    Context 'Etype drift detection - GPO and AD agree' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = 24
                    RC4DefaultDisablementPhase     = 2
                    GPOSupportedEncryptionTypes    = [int]0x80000018
                }
            }
            Mock -ModuleName 'RC4-ADAssessment' Get-ADComputer {
                [PSCustomObject]@{ 'msDS-SupportedEncryptionTypes' = 0x18 }
            }
        }

        It 'Reports zero drift when GPO effective value matches AD attribute' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.TotalEtypeDrift | Should -Be 0
        }

        It 'Returns empty EtypeDrift array' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.EtypeDrift.Count | Should -Be 0
        }

        It 'Stores GPO etype in per-DC detail' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.Details[0].GPOSupportedEncryptionTypes | Should -Be ([int]0x80000018)
        }
    }

    Context 'Etype drift detection - GPO and AD disagree' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = 24
                    RC4DefaultDisablementPhase     = 2
                    GPOSupportedEncryptionTypes    = [int]0x80000018
                }
            }
            Mock -ModuleName 'RC4-ADAssessment' Get-ADComputer {
                [PSCustomObject]@{ 'msDS-SupportedEncryptionTypes' = 0x1F }
            }
        }

        It 'Detects drift when GPO effective value differs from AD attribute' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.TotalEtypeDrift | Should -Be 1
        }

        It 'Populates EtypeDrift with correct DC name' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.EtypeDrift[0].DCName | Should -Be 'dc01.contoso.com'
        }

        It 'Records GPO effective value without high bit' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.EtypeDrift[0].GPOEffective | Should -Be 0x18
        }

        It 'Records AD msDS-SupportedEncryptionTypes value' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.EtypeDrift[0].MsDsSET | Should -Be 0x1F
        }
    }

    Context 'Etype drift detection - no GPO etype configured' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = $null
                    RC4DefaultDisablementPhase     = $null
                    GPOSupportedEncryptionTypes    = $null
                }
            }
        }

        It 'Reports zero drift when GPO etype is not configured' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.TotalEtypeDrift | Should -Be 0
        }
    }

    Context 'Etype drift detection - multiple DCs with mixed results' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @(
                    [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' },
                    [PSCustomObject]@{ Name = 'DC02'; HostName = 'dc02.contoso.com'; ComputerObjectDN = 'CN=DC02,OU=Domain Controllers,DC=contoso,DC=com' }
                )
            }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = 24
                    RC4DefaultDisablementPhase     = 2
                    GPOSupportedEncryptionTypes    = [int]0x80000018
                }
            }
            $script:adComputerCallCount = 0
            Mock -ModuleName 'RC4-ADAssessment' Get-ADComputer {
                $script:adComputerCallCount++
                if ($script:adComputerCallCount -eq 1) {
                    [PSCustomObject]@{ 'msDS-SupportedEncryptionTypes' = 0x18 }
                }
                else {
                    [PSCustomObject]@{ 'msDS-SupportedEncryptionTypes' = 0x1C }
                }
            }
        }

        It 'Detects drift only on the DC where values differ' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.TotalEtypeDrift | Should -Be 1
            $result.EtypeDrift[0].DCName | Should -Be 'dc02.contoso.com'
        }
    }
}
}
