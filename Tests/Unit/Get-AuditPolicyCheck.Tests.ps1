BeforeAll {
    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADDomainController' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomainController { param([string]$DomainName, [switch]$Discover, [string]$Filter, [string]$Server, $ErrorAction) }
    }
}

Describe 'Get-AuditPolicyCheck' {
    BeforeEach {
        Mock -ModuleName 'RC4ADCheck' Write-Host {}
        Mock -ModuleName 'RC4ADCheck' Get-ADDomain {
            [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
        }
        Mock -ModuleName 'RC4ADCheck' Get-ADDomainController {
            @([PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' })
        }
    }

    Context 'When both audit policies are enabled' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Invoke-Command {
                @{
                    AuthService = 'Kerberos Authentication Service  Success and Failure'
                    TicketOps   = 'Kerberos Service Ticket Operations  Success and Failure'
                }
            }
        }

        It 'Returns OK status' {
            $result = Get-AuditPolicyCheck -ServerParams @{ Server = 'dc01.contoso.com' }
            $result.Status | Should -Be 'OK'
        }

        It 'Returns both policies enabled' {
            $result = Get-AuditPolicyCheck -ServerParams @{ Server = 'dc01.contoso.com' }
            $result.KerberosAuthServiceEnabled | Should -BeTrue
            $result.KerberosTicketOpsEnabled | Should -BeTrue
        }
    }

    Context 'When no audit policies are enabled' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Invoke-Command {
                @{
                    AuthService = 'Kerberos Authentication Service  No Auditing'
                    TicketOps   = 'Kerberos Service Ticket Operations  No Auditing'
                }
            }
        }

        It 'Returns CRITICAL status' {
            $result = Get-AuditPolicyCheck -ServerParams @{ Server = 'dc01.contoso.com' }
            $result.Status | Should -Be 'CRITICAL'
        }
    }

    Context 'When Invoke-Command fails' {
        BeforeEach {
            Mock -ModuleName 'RC4ADCheck' Invoke-Command { throw 'Access denied' }
        }

        It 'Returns UNKNOWN status' {
            $result = Get-AuditPolicyCheck -ServerParams @{ Server = 'dc01.contoso.com' }
            $result.Status | Should -Be 'UNKNOWN'
        }
    }
}
