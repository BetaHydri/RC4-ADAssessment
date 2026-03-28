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
    if (-not (Get-Command 'Get-ADObject' -ErrorAction SilentlyContinue)) {
        function global:Get-ADObject { param([string]$Identity, [string]$Filter, [string]$SearchBase, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-GPInheritance' -ErrorAction SilentlyContinue)) {
        function global:Get-GPInheritance { param([string]$Target, [string]$Domain, [string]$Server, $ErrorAction) }
    }
}

Describe 'Get-DomainControllerEncryption' {
    BeforeEach {
        Mock -ModuleName 'RC4ADCheck' Write-Host {}
        Mock -ModuleName 'RC4ADCheck' Get-ADDomain {
            [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
        }
        Mock -ModuleName 'RC4ADCheck' Get-ADComputer -ParameterFilter { $Identity -eq 'AzureADKerberos' } { throw 'not found' }
        Mock -ModuleName 'RC4ADCheck' Get-GPInheritance { $null }
    }

    Context 'When all DCs have AES configured' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADDomainController {
                @(
                    [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' },
                    [PSCustomObject]@{ Name = 'DC02'; HostName = 'dc02.contoso.com'; ComputerObjectDN = 'CN=DC02,OU=Domain Controllers,DC=contoso,DC=com' }
                )
            }
            Mock -ModuleName 'RC4ADCheck' Get-ADComputer -ParameterFilter { $Identity -ne 'AzureADKerberos' } {
                [PSCustomObject]@{ Name = 'DC'; 'msDS-SupportedEncryptionTypes' = 24; OperatingSystem = 'Windows Server 2022' }
            }
        }

        It 'Returns correct total DC count' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.TotalDCs | Should -Be 2
        }

        It 'Reports all DCs as AES configured' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.AESConfigured | Should -Be 2
        }

        It 'Reports no RC4 or DES configured' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.RC4Configured | Should -Be 0
            $result.DESConfigured | Should -Be 0
        }
    }

    Context 'When a DC has RC4' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4ADCheck' Get-ADComputer -ParameterFilter { $Identity -ne 'AzureADKerberos' } {
                [PSCustomObject]@{ Name = 'DC01'; 'msDS-SupportedEncryptionTypes' = 28; OperatingSystem = 'Windows Server 2022' }
            }
        }

        It 'Counts both AES and RC4' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.AESConfigured | Should -Be 1
            $result.RC4Configured | Should -Be 1
        }
    }
}
