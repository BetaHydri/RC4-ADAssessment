InModuleScope 'RC4-ADAssessment' {
Describe 'Show-ForestSummary' {
    BeforeEach {
        Mock -ModuleName 'RC4-ADAssessment' Write-Host {}
    }

    It 'Does not throw with a single domain result' {
        $forestResults = @{
            ForestName    = 'contoso.com'
            TotalDomains  = 1
            DomainResults = @(
                @{
                    Domain = 'contoso.com'
                    Status = 'OK'
                    Data   = @{
                        DomainControllers = @{ Details = @(
                            @{ Name = 'DC01'; Status = 'OK'; EncryptionTypes = 'AES256-HMAC'; EncryptionValue = 16; OperatingSystem = 'Windows Server 2022' }
                        )}
                        EventLogs = $null
                        Trusts    = @{ Details = @() }
                    }
                }
            )
        }
        { Show-ForestSummary -ForestResults $forestResults } | Should -Not -Throw
    }

    It 'Does not throw with empty domain results' {
        $forestResults = @{
            ForestName    = 'contoso.com'
            TotalDomains  = 0
            DomainResults = @()
        }
        { Show-ForestSummary -ForestResults $forestResults } | Should -Not -Throw
    }

    It 'Handles a failed domain without throwing' {
        $forestResults = @{
            ForestName    = 'contoso.com'
            TotalDomains  = 1
            DomainResults = @(
                @{ Domain = 'failed.contoso.com'; Status = 'Failed'; Data = $null }
            )
        }
        { Show-ForestSummary -ForestResults $forestResults } | Should -Not -Throw
    }
}
}
