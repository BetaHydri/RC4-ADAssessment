#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for the orchestration wrapper functions.
.DESCRIPTION
    Tests for Invoke-RC4Assessment, Invoke-ForestAssessment, and Invoke-AssessmentComparison.
    All AD cmdlets and sub-functions are mocked.
.NOTES
    Requires: Pester 5.x
#>

BeforeAll {
    $script:Version = '3.0.0-preview'
    $script:AssessmentTimestamp = Get-Date

    # Create AD module stubs
    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADComputer' -ErrorAction SilentlyContinue)) {
        function global:Get-ADComputer { param([string]$Identity, [string]$Filter, [string]$SearchBase, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADUser' -ErrorAction SilentlyContinue)) {
        function global:Get-ADUser { param([string]$Identity, [string]$Filter, [string[]]$Properties, [string]$SearchBase, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADDomainController' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomainController { param([string]$DomainName, [switch]$Discover, [string]$Filter, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADTrust' -ErrorAction SilentlyContinue)) {
        function global:Get-ADTrust { param([string]$Filter, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADServiceAccount' -ErrorAction SilentlyContinue)) {
        function global:Get-ADServiceAccount { param([string]$Identity, [string]$Filter, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADForest' -ErrorAction SilentlyContinue)) {
        function global:Get-ADForest { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADObject' -ErrorAction SilentlyContinue)) {
        function global:Get-ADObject { param([string]$Identity, [string]$Filter, [string]$SearchBase, [string[]]$Properties, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-GPInheritance' -ErrorAction SilentlyContinue)) {
        function global:Get-GPInheritance { param([string]$Target, [string]$Domain, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-GPOReport' -ErrorAction SilentlyContinue)) {
        function global:Get-GPOReport { param([guid]$Guid, [string]$ReportType, [string]$Domain, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Test-Connection' -ErrorAction SilentlyContinue)) {
        function global:Test-Connection { param([string]$ComputerName, [int]$Count, [switch]$Quiet, $ErrorAction) $true }
    }
}

# ============================================================
# Invoke-RC4Assessment
# ============================================================

Describe 'Invoke-RC4Assessment' {
    BeforeEach {
        Mock -ModuleName 'RC4ADCheck' Write-Host {}
        Mock -ModuleName 'RC4ADCheck' Write-Warning {}
        Mock -ModuleName 'RC4ADCheck' Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'contoso.com'
                DistinguishedName = 'DC=contoso,DC=com'
            }
        }
        Mock -ModuleName 'RC4ADCheck' Get-ADDomainController { @() }
        Mock -ModuleName 'RC4ADCheck' Get-ADComputer { $null }
        Mock -ModuleName 'RC4ADCheck' Get-ADTrust { $null }
        Mock -ModuleName 'RC4ADCheck' Get-ADUser {
            if ("$Identity" -eq 'krbtgt') {
                return [PSCustomObject]@{
                    SamAccountName                  = 'krbtgt'
                    PasswordLastSet                 = (Get-Date).AddDays(-90)
                    pwdLastSet                      = $null
                    'msDS-SupportedEncryptionTypes' = 24
                    WhenChanged                     = (Get-Date).AddDays(-90)
                }
            }
            return $null
        }
        Mock -ModuleName 'RC4ADCheck' Get-ADServiceAccount { $null }
        Mock -ModuleName 'RC4ADCheck' Test-Connection { $true }
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

    It 'Populates AssessmentDate' {
        $result = Invoke-RC4Assessment
        $result.AssessmentDate | Should -Not -BeNullOrEmpty
    }

    It 'Populates DomainControllers assessment' {
        $result = Invoke-RC4Assessment
        $result.DomainControllers | Should -Not -BeNullOrEmpty
    }

    It 'Populates Trusts assessment' {
        $result = Invoke-RC4Assessment
        $result.Trusts | Should -Not -BeNullOrEmpty
    }

    It 'Populates Accounts assessment' {
        $result = Invoke-RC4Assessment
        $result.Accounts | Should -Not -BeNullOrEmpty
    }

    It 'Populates KdcRegistry assessment' {
        $result = Invoke-RC4Assessment
        $result.KdcRegistry | Should -Not -BeNullOrEmpty
    }

    It 'Accepts -Domain parameter' {
        $result = Invoke-RC4Assessment -Domain 'child.contoso.com'
        $result | Should -Not -BeNullOrEmpty
    }

    It 'Skips event logs without -AnalyzeEventLogs' {
        $result = Invoke-RC4Assessment
        $result.EventLogs | Should -BeNullOrEmpty
    }

    It 'Returns OK status when no issues found' {
        $result = Invoke-RC4Assessment
        $result.OverallStatus | Should -Be 'OK'
    }
}

# ============================================================
# Invoke-AssessmentComparison
# ============================================================

Describe 'Invoke-AssessmentComparison' {
    BeforeAll {
        # Create temp JSON files for comparison testing
        $script:baselineFile = Join-Path ([System.IO.Path]::GetTempPath()) "baseline_$(Get-Random).json"
        $script:currentFile = Join-Path ([System.IO.Path]::GetTempPath()) "current_$(Get-Random).json"

        $baselineData = @{
            Domain            = 'contoso.com'
            OverallStatus     = 'WARNING'
            Version           = '2.9.0'
            AssessmentDate    = '2026-03-01T10:00:00'
            DomainControllers = @{
                TotalDCs       = 3
                AESConfigured  = 2
                RC4Configured  = 1
                DESConfigured  = 0
                NotConfigured  = 0
            }
            Trusts = @{
                TotalTrusts = 1
                RC4Risk     = 1
                DESRisk     = 0
            }
            Accounts = @{
                KRBTGT = @{ Status = 'OK'; PasswordAgeDays = 90 }
                TotalRC4OnlySvc   = 2
                TotalRC4OnlyMSA   = 0
                TotalDESFlag      = 0
                TotalStaleSvc     = 1
                TotalMissingAES   = 3
                TotalRC4Exception = 1
                TotalDESEnabled   = 0
            }
            EventLogs = @{
                TotalEventsAnalyzed = 5000
                RC4Tickets          = 100
                DESTickets          = 5
                AESTickets          = 4895
            }
            KdcRegistry = @{
                DefaultDomainSupportedEncTypes = @{ Value = $null; Status = 'Not Set' }
                RC4DefaultDisablementPhase     = @{ Value = $null; Status = 'Not Set' }
            }
            KdcSvcEvents = @{
                TotalEvents = 0
                Status      = 'OK'
            }
        }

        $currentData = @{
            Domain            = 'contoso.com'
            OverallStatus     = 'OK'
            Version           = '2.9.0'
            AssessmentDate    = '2026-03-27T10:00:00'
            DomainControllers = @{
                TotalDCs       = 3
                AESConfigured  = 3
                RC4Configured  = 0
                DESConfigured  = 0
                NotConfigured  = 0
            }
            Trusts = @{
                TotalTrusts = 1
                RC4Risk     = 0
                DESRisk     = 0
            }
            Accounts = @{
                KRBTGT = @{ Status = 'OK'; PasswordAgeDays = 30 }
                TotalRC4OnlySvc   = 0
                TotalRC4OnlyMSA   = 0
                TotalDESFlag      = 0
                TotalStaleSvc     = 0
                TotalMissingAES   = 1
                TotalRC4Exception = 0
                TotalDESEnabled   = 0
            }
            EventLogs = @{
                TotalEventsAnalyzed = 6000
                RC4Tickets          = 10
                DESTickets          = 0
                AESTickets          = 5990
            }
            KdcRegistry = @{
                DefaultDomainSupportedEncTypes = @{ Value = 24; Status = 'AES Only' }
                RC4DefaultDisablementPhase     = @{ Value = 1; Status = 'Audit Mode' }
            }
            KdcSvcEvents = @{
                TotalEvents = 0
                Status      = 'OK'
            }
        }

        $baselineData | ConvertTo-Json -Depth 10 | Set-Content $script:baselineFile -Encoding UTF8
        $currentData | ConvertTo-Json -Depth 10 | Set-Content $script:currentFile -Encoding UTF8
    }

    AfterAll {
        Remove-Item $script:baselineFile -Force -ErrorAction SilentlyContinue
        Remove-Item $script:currentFile -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        Mock -ModuleName 'RC4ADCheck' Write-Host {}
    }

    It 'Does not throw with valid JSON files' {
        { Invoke-AssessmentComparison -BaselineFile $script:baselineFile -CurrentFile $script:currentFile } | Should -Not -Throw
    }

    It 'Validates baseline file exists' {
        { Invoke-AssessmentComparison -BaselineFile 'nonexistent.json' -CurrentFile $script:currentFile } | Should -Throw
    }

    It 'Validates current file exists' {
        { Invoke-AssessmentComparison -BaselineFile $script:baselineFile -CurrentFile 'nonexistent.json' } | Should -Throw
    }
}

# ============================================================
# Invoke-ForestAssessment (smoke test)
# ============================================================

Describe 'Invoke-ForestAssessment' {
    It 'Has valid function definition' {
        $cmd = Get-Command Invoke-ForestAssessment -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
    }

    It 'Accepts ForestName parameter' {
        $cmd = Get-Command Invoke-ForestAssessment
        $cmd.Parameters.Keys | Should -Contain 'ForestName'
    }

    It 'Accepts Parallel parameter' {
        $cmd = Get-Command Invoke-ForestAssessment
        $cmd.Parameters.Keys | Should -Contain 'Parallel'
    }

    It 'Accepts MaxParallelDomains parameter' {
        $cmd = Get-Command Invoke-ForestAssessment
        $cmd.Parameters.Keys | Should -Contain 'MaxParallelDomains'
    }

    It 'Accepts AnalyzeEventLogs parameter' {
        $cmd = Get-Command Invoke-ForestAssessment
        $cmd.Parameters.Keys | Should -Contain 'AnalyzeEventLogs'
    }
}
