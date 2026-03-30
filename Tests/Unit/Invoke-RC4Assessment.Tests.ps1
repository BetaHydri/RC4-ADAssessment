BeforeAll {
    $script:Version = '4.0.0'
    $script:AssessmentTimestamp = Get-Date

    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADDomainController' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomainController { param([string]$DomainName, [switch]$Discover, [string]$Filter, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADComputer' -ErrorAction SilentlyContinue)) {
        function global:Get-ADComputer { param([string]$Identity, [string]$Filter, [string]$SearchBase, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADTrust' -ErrorAction SilentlyContinue)) {
        function global:Get-ADTrust { param([string]$Filter, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADUser' -ErrorAction SilentlyContinue)) {
        function global:Get-ADUser { param([string]$Identity, [string]$Filter, [string[]]$Properties, [string]$SearchBase, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADServiceAccount' -ErrorAction SilentlyContinue)) {
        function global:Get-ADServiceAccount { param([string]$Identity, [string]$Filter, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADObject' -ErrorAction SilentlyContinue)) {
        function global:Get-ADObject { param([string]$Identity, [string]$Filter, [string]$SearchBase, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-GPInheritance' -ErrorAction SilentlyContinue)) {
        function global:Get-GPInheritance { param([string]$Target, [string]$Domain, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Test-Connection' -ErrorAction SilentlyContinue)) {
        function global:Test-Connection { param([string]$ComputerName, [int]$Count, [switch]$Quiet, $ErrorAction) $true }
    }
}

Describe 'Invoke-RC4Assessment' {
    BeforeEach {
        Mock -ModuleName 'RC4-ADAssessment' Write-Host {}
        Mock -ModuleName 'RC4-ADAssessment' Write-Warning {}
        Mock -ModuleName 'RC4-ADAssessment' Get-ADDomain {
            [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
        }
        Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController { @() }
        Mock -ModuleName 'RC4-ADAssessment' Get-ADComputer { $null }
        Mock -ModuleName 'RC4-ADAssessment' Get-ADTrust { $null }
        Mock -ModuleName 'RC4-ADAssessment' Get-ADUser {
            if ("$Identity" -eq 'krbtgt') {
                return [PSCustomObject]@{
                    SamAccountName                  = 'krbtgt'
                    PasswordLastSet                 = (Get-Date).AddDays(-90)
                    pwdLastSet                      = (Get-Date).AddDays(-90).ToFileTime()
                    'msDS-SupportedEncryptionTypes' = 24
                    WhenChanged                     = (Get-Date).AddDays(-90)
                }
            }
            return $null
        }
        Mock -ModuleName 'RC4-ADAssessment' Get-ADServiceAccount { $null }
        Mock -ModuleName 'RC4-ADAssessment' Test-Connection { $true }
    }

    It 'Returns a results hashtable' {
        $result = Invoke-RC4Assessment
        $result | Should -BeOfType [hashtable]
    }

    It 'Populates Domain in results' {
        $result = Invoke-RC4Assessment
        $result.Domain | Should -Be 'contoso.com'
    }

    It 'Populates OverallStatus' {
        $result = Invoke-RC4Assessment
        $result.OverallStatus | Should -BeIn @('OK', 'WARNING', 'CRITICAL')
    }

    It 'Populates DomainControllers assessment' {
        $result = Invoke-RC4Assessment
        $result.DomainControllers | Should -Not -BeNullOrEmpty
    }

    It 'Populates Accounts assessment' {
        $result = Invoke-RC4Assessment
        $result.Accounts | Should -Not -BeNullOrEmpty
    }

    It 'Skips event logs without -AnalyzeEventLogs' {
        $result = Invoke-RC4Assessment
        $result.EventLogs | Should -BeNullOrEmpty
    }

    It 'Accepts -DeepScan switch' {
        $result = Invoke-RC4Assessment -DeepScan
        $result | Should -BeOfType [hashtable]
        $result.Accounts | Should -Not -BeNullOrEmpty
    }
}
