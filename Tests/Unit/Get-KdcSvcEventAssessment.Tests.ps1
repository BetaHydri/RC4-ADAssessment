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

InModuleScope 'RC4-ADAssessment' {
Describe 'Get-KdcSvcEventAssessment' {
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

        It 'Returns empty QueriedDCs' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.QueriedDCs.Count | Should -Be 0
        }
    }

    Context 'When DC returns no KDCSVC events' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command { @() }
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
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command { throw 'WinRM error' }
        }

        It 'Adds DC to FailedDCs' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.FailedDCs.Count | Should -Be 1
        }
    }

    Context 'XPath filter includes both KDC provider names' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            $script:capturedFilterXml = $null
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command {
                $script:capturedFilterXml = $ArgumentList[0]
                @()
            }
        }

        It 'Queries for KDCSVC provider' {
            Get-KdcSvcEventAssessment -ServerParams @{}
            $script:capturedFilterXml | Should -Match "Provider\[@Name='KDCSVC'\]"
        }

        It 'Queries for Microsoft-Windows-Kerberos-Key-Distribution-Center provider' {
            Get-KdcSvcEventAssessment -ServerParams @{}
            $script:capturedFilterXml | Should -Match "Provider\[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center'\]"
        }
    }
}
}
