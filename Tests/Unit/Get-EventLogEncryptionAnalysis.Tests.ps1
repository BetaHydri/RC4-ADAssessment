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
Describe 'Get-EventLogEncryptionAnalysis' {
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

        It 'Returns zero events analyzed' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.EventsAnalyzed | Should -Be 0
        }
    }

    Context 'When DC event log query returns no events' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command { @() }
        }

        It 'Returns zero ticket counts' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.RC4Tickets | Should -Be 0
            $result.DESTickets | Should -Be 0
            $result.AESTickets | Should -Be 0
        }

        It 'Returns zero session key counts' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.SessionKeyRC4 | Should -Be 0
            $result.SessionKeyDES | Should -Be 0
            $result.SessionKeyAES | Should -Be 0
            $result.RC4SessionKeyAccounts | Should -HaveCount 0
        }
    }

    Context 'When DC event log query fails' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command { throw 'Access denied' }
            Mock -ModuleName 'RC4-ADAssessment' Get-WinEvent { throw 'RPC failed' }
        }

        It 'Adds DC to FailedDCs' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.FailedDCs.Count | Should -Be 1
        }
    }

    Context 'When Invoke-Command throws "No events were found"' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4-ADAssessment' Test-Connection { $true }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command {
                throw 'No events were found that match the specified selection criteria.'
            }
        }

        It 'Treats DC as successfully queried, not failed' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.QueriedDCs | Should -Contain 'dc01.contoso.com'
            $result.FailedDCs.Count | Should -Be 0
        }

        It 'Returns zero ticket counts' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.RC4Tickets | Should -Be 0
            $result.AESTickets | Should -Be 0
            $result.EventsAnalyzed | Should -Be 0
        }
    }

    Context 'When events contain mixed ticket and session key encryption types' {
        BeforeEach {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
            }
            Mock -ModuleName 'RC4-ADAssessment' Test-Connection { $true }
            Mock -ModuleName 'RC4-ADAssessment' Invoke-Command {
                @(
                    # AES ticket with AES session key
                    [PSCustomObject]@{ EventId = 4768; TargetUserName = 'user1'; TicketEncryptionType = '0x12'; SessionEncryptionType = '0x12'; ServiceName = 'krbtgt' },
                    # AES ticket with RC4 session key (the gap we want to detect)
                    [PSCustomObject]@{ EventId = 4769; TargetUserName = 'svc_legacy'; TicketEncryptionType = '0x12'; SessionEncryptionType = '0x17'; ServiceName = 'HTTP/web01' },
                    # RC4 ticket with RC4 session key
                    [PSCustomObject]@{ EventId = 4769; TargetUserName = 'svc_old'; TicketEncryptionType = '0x17'; SessionEncryptionType = '0x17'; ServiceName = 'CIFS/fs01' },
                    # AES ticket with no session key field (older event format)
                    [PSCustomObject]@{ EventId = 4768; TargetUserName = 'user2'; TicketEncryptionType = '0x11'; SessionEncryptionType = $null; ServiceName = 'krbtgt' }
                )
            }
        }

        It 'Counts ticket encryption types correctly' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.AESTickets | Should -Be 3
            $result.RC4Tickets | Should -Be 1
            $result.RC4Accounts | Should -Contain 'svc_old'
        }

        It 'Counts session key encryption types correctly' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.SessionKeyAES | Should -Be 1
            $result.SessionKeyRC4 | Should -Be 2
        }

        It 'Tracks RC4 session key accounts separately' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.RC4SessionKeyAccounts | Should -Contain 'svc_legacy'
            $result.RC4SessionKeyAccounts | Should -Contain 'svc_old'
        }

        It 'Handles events without SessionEncryptionType gracefully' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.EventsAnalyzed | Should -Be 4
            # 3 events have session key data, 1 does not
            ($result.SessionKeyAES + $result.SessionKeyRC4 + $result.SessionKeyDES + $result.SessionKeyUnknown) | Should -Be 3
        }

        It 'Includes session key stats in per-DC stats' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.PerDcStats['dc01.contoso.com'].SessionKeyRC4 | Should -Be 2
            $result.PerDcStats['dc01.contoso.com'].SessionKeyAES | Should -Be 1
        }
    }
}
}
