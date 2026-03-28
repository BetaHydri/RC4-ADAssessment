BeforeAll {
    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADDomainController' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomainController { param([string]$DomainName, [switch]$Discover, [string]$Filter, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADComputer' -ErrorAction SilentlyContinue)) {
        function global:Get-ADComputer { param([string]$Identity, [string]$Filter, [string]$SearchBase, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
}

Describe 'Get-KdcSvcEventAssessment' {
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

        It 'Returns empty QueriedDCs' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.QueriedDCs.Count | Should -Be 0
        }
    }

    Context 'When DC returns no KDCSVC events' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4ADCheck' Invoke-Command { @() }
        }

        It 'Returns OK status' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.Status | Should -Be 'OK'
        }

        It 'Returns zero total events' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.TotalEvents | Should -Be 0
        }
    }

    Context 'When WinRM to DC fails' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4ADCheck' Invoke-Command { throw 'WinRM error' }
        }

        It 'Adds DC to FailedDCs' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.FailedDCs.Count | Should -Be 1
        }
    }
}
