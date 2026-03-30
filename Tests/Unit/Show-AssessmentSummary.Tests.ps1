InModuleScope 'RC4ADCheck' {
Describe 'Show-AssessmentSummary' {
    BeforeEach {
        Mock -ModuleName 'RC4ADCheck' Write-Host {}
    }

    It 'Does not throw with a complete results hashtable' {
        $results = @{
            DomainControllers = @{ TotalDCs = 1; AESConfigured = 1; RC4Configured = 0; DESConfigured = 0; Details = @(
                @{ Name = 'DC01'; Status = 'AES Configured'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC'; EncryptionValue = 24; OperatingSystem = 'Windows Server 2022' }
            )}
            Accounts = @{ KRBTGT = @{ Status = 'OK'; PasswordAgeDays = 90 }; TotalRC4OnlySvc = 0; TotalDESFlag = 0; DESFlagAccounts = @(); RC4OnlySvcAccounts = @(); RC4ExceptionAccounts = @(); MissingAESKeyAccounts = @(); StaleSvcAccounts = @(); MSADetails = @() }
            EventLogs = $null
            Trusts = @{ TotalTrusts = 0; Details = @() }
            KdcRegistry = @{ DefaultDomainSupportedEncTypes = @{ Status = 'NOT SET' }; RC4DefaultDisablementPhase = @{ Status = 'NOT SET' }; QueriedDCs = @(); FailedDCs = @() }
            KdcSvcEvents = $null
            AuditPolicy = $null
        }
        { Show-AssessmentSummary -Results $results } | Should -Not -Throw
    }

    It 'Does not throw with null event logs' {
        $results = @{
            DomainControllers = @{ TotalDCs = 0; Details = @() }
            Accounts = @{ KRBTGT = @{ Status = 'OK'; PasswordAgeDays = 30 }; TotalRC4OnlySvc = 0; TotalDESFlag = 0; DESFlagAccounts = @(); RC4OnlySvcAccounts = @(); RC4ExceptionAccounts = @(); MissingAESKeyAccounts = @(); StaleSvcAccounts = @(); MSADetails = @() }
            EventLogs = $null
            Trusts = @{ TotalTrusts = 0; Details = @() }
            KdcRegistry = @{ DefaultDomainSupportedEncTypes = @{ Status = 'NOT SET' }; RC4DefaultDisablementPhase = @{ Status = 'NOT SET' }; QueriedDCs = @(); FailedDCs = @() }
            KdcSvcEvents = $null
            AuditPolicy = $null
        }
        { Show-AssessmentSummary -Results $results } | Should -Not -Throw
    }
}
}
