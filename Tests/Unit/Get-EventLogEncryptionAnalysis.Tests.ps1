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

InModuleScope 'RC4ADCheck' {
Describe 'Get-EventLogEncryptionAnalysis' {
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

        It 'Returns zero events analyzed' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.EventsAnalyzed | Should -Be 0
        }
    }

    Context 'When DC event log query returns no events' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4ADCheck' Invoke-Command { @() }
        }

        It 'Returns zero ticket counts' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.RC4Tickets | Should -Be 0
            $result.DESTickets | Should -Be 0
            $result.AESTickets | Should -Be 0
        }
    }

    Context 'When DC event log query fails' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4ADCheck' Invoke-Command { throw 'Access denied' }
            Mock -ModuleName 'RC4ADCheck' Get-WinEvent { throw 'RPC failed' }
        }

        It 'Adds DC to FailedDCs' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.FailedDCs.Count | Should -Be 1
        }
    }
}
}
