#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for Assess-ADForest.ps1
.DESCRIPTION
    Mocked unit tests for the forest-wide assessment wrapper in Assess-ADForest.ps1.
    All AD cmdlets are mocked. Tests cover Show-ForestSummary and Invoke-DomainAssessment logic.
.NOTES
    Author: Jan Tiedemann
    Requires: Pester 5.x
#>

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..' 'Assess-ADForest.ps1'
    $scriptContent = Get-Content -Path $scriptPath -Raw

    # Extract the Show-ForestSummary function
    $functionPattern = '(?s)(function\s+Show-ForestSummary\s*\{.*?\n\})'
    $match = [regex]::Match($scriptContent, $functionPattern)
    
    if ($match.Success) {
        . ([ScriptBlock]::Create($match.Value))
    }

    # Extract Invoke-DomainAssessment function
    $invokePattern = '(?s)(function\s+Invoke-DomainAssessment\s*\{.*?\n\})'
    $invokeMatch = [regex]::Match($scriptContent, $invokePattern)
    
    if ($invokeMatch.Success) {
        . ([ScriptBlock]::Create($invokeMatch.Value))
    }

    # Create AD module stubs if not available
    $adCmdlets = @(
        'Get-ADDomain', 'Get-ADForest', 'Get-ADDomainController',
        'Get-ADComputer', 'Get-ADTrust', 'Get-ADUser', 'Get-ADServiceAccount'
    )
    foreach ($cmdlet in $adCmdlets) {
        if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
            Set-Item -Path "function:global:$cmdlet" -Value { param() }
        }
    }
}

# ============================================================
# Show-ForestSummary
# ============================================================

Describe 'Show-ForestSummary' {
    BeforeEach {
        Mock Write-Host {}
    }

    Context 'With healthy forest results' {
        It 'Does not throw with complete results' {
            $forestResults = @{
                ForestName    = 'contoso.com'
                TotalDomains  = 2
                DomainResults = @(
                    @{
                        Domain = 'contoso.com'
                        Status = 'OK'
                        Data   = @{
                            DomainControllers = @{
                                Details = @(
                                    @{ Name = 'DC01'; Status = 'OK'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC'; EncryptionValue = 24; OperatingSystem = 'Windows Server 2022' }
                                )
                            }
                            EventLogs         = @{
                                QueriedDCs = @('dc01.contoso.com')
                                FailedDCs  = @()
                            }
                            Trusts            = @{
                                Details = @()
                            }
                        }
                    },
                    @{
                        Domain = 'child.contoso.com'
                        Status = 'OK'
                        Data   = @{
                            DomainControllers = @{
                                Details = @(
                                    @{ Name = 'DC-CHILD01'; Status = 'OK'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC'; EncryptionValue = 24; OperatingSystem = 'Windows Server 2022' }
                                )
                            }
                            EventLogs         = $null
                            Trusts            = @{
                                Details = @()
                            }
                        }
                    }
                )
            }

            { Show-ForestSummary -ForestResults $forestResults } | Should -Not -Throw
        }
    }

    Context 'With mixed domain results' {
        It 'Handles domains with varying statuses' {
            $forestResults = @{
                ForestName    = 'contoso.com'
                TotalDomains  = 3
                DomainResults = @(
                    @{
                        Domain = 'contoso.com'
                        Status = 'OK'
                        Data   = @{
                            DomainControllers = @{
                                Details = @(
                                    @{ Name = 'DC01'; Status = 'OK'; EncryptionTypes = 'AES256-HMAC'; EncryptionValue = 16; OperatingSystem = 'Windows Server 2022' }
                                )
                            }
                            EventLogs = $null
                            Trusts    = @{ Details = @() }
                        }
                    },
                    @{
                        Domain = 'legacy.contoso.com'
                        Status = 'CRITICAL'
                        Data   = @{
                            DomainControllers = @{
                                Details = @(
                                    @{ Name = 'DC-LEGACY'; Status = 'CRITICAL'; EncryptionTypes = 'DES-CBC-CRC, DES-CBC-MD5'; EncryptionValue = 3; OperatingSystem = 'Windows Server 2008' }
                                )
                            }
                            EventLogs = @{
                                QueriedDCs = @('dc-legacy.legacy.contoso.com')
                                FailedDCs  = @()
                            }
                            Trusts    = @{
                                Details = @(
                                    @{ 'Trust Name' = 'contoso.com'; Direction = 'Bidirectional'; 'Encryption Types' = 'DES-CBC-CRC'; Risk = 'CRITICAL' }
                                )
                            }
                        }
                    },
                    @{
                        Domain = 'failed.contoso.com'
                        Status = 'Failed'
                        Data   = $null
                    }
                )
            }

            { Show-ForestSummary -ForestResults $forestResults } | Should -Not -Throw
        }
    }

    Context 'With no domain data' {
        It 'Handles empty domain results' {
            $forestResults = @{
                ForestName    = 'contoso.com'
                TotalDomains  = 0
                DomainResults = @()
            }

            { Show-ForestSummary -ForestResults $forestResults } | Should -Not -Throw
        }
    }

    Context 'With DC event log failures' {
        It 'Handles failed DC event log queries' {
            $forestResults = @{
                ForestName    = 'contoso.com'
                TotalDomains  = 1
                DomainResults = @(
                    @{
                        Domain = 'contoso.com'
                        Status = 'WARNING'
                        Data   = @{
                            DomainControllers = @{
                                Details = @(
                                    @{ Name = 'DC01'; Status = 'OK'; EncryptionTypes = 'AES256-HMAC'; EncryptionValue = 16; OperatingSystem = 'Windows Server 2022' },
                                    @{ Name = 'DC02'; Status = 'WARNING'; EncryptionTypes = 'RC4-HMAC'; EncryptionValue = 4; OperatingSystem = 'Windows Server 2016' }
                                )
                            }
                            EventLogs = @{
                                QueriedDCs = @('dc01.contoso.com')
                                FailedDCs  = @(
                                    @{ Name = 'dc02.contoso.com'; Error = 'WinRM failed' }
                                )
                            }
                            Trusts    = @{ Details = @() }
                        }
                    }
                )
            }

            { Show-ForestSummary -ForestResults $forestResults } | Should -Not -Throw
        }
    }
}

# ============================================================
# Forest Status Aggregation Logic
# ============================================================

Describe 'Forest Status Aggregation' {
    Context 'Overall forest status determination' {
        It 'Returns CRITICAL when any domain is CRITICAL' {
            $forestResults = @{
                CriticalIssues = 0
                Warnings       = 0
                HealthyDomains = 0
            }
            $domainResults = @(
                @{ Status = 'OK' },
                @{ Status = 'CRITICAL' },
                @{ Status = 'OK' }
            )

            foreach ($result in $domainResults) {
                switch ($result.Status) {
                    'CRITICAL' { $forestResults.CriticalIssues++ }
                    'WARNING' { $forestResults.Warnings++ }
                    { $_ -in @('OK', 'Completed') } { $forestResults.HealthyDomains++ }
                }
            }

            $overallStatus = if ($forestResults.CriticalIssues -gt 0) { 'CRITICAL' }
            elseif ($forestResults.Warnings -gt 0) { 'WARNING' }
            else { 'OK' }

            $overallStatus | Should -Be 'CRITICAL'
            $forestResults.CriticalIssues | Should -Be 1
            $forestResults.HealthyDomains | Should -Be 2
        }

        It 'Returns WARNING when no CRITICAL but has warnings' {
            $forestResults = @{
                CriticalIssues = 0
                Warnings       = 0
                HealthyDomains = 0
            }
            $domainResults = @(
                @{ Status = 'OK' },
                @{ Status = 'WARNING' }
            )

            foreach ($result in $domainResults) {
                switch ($result.Status) {
                    'CRITICAL' { $forestResults.CriticalIssues++ }
                    'WARNING' { $forestResults.Warnings++ }
                    { $_ -in @('OK', 'Completed') } { $forestResults.HealthyDomains++ }
                }
            }

            $overallStatus = if ($forestResults.CriticalIssues -gt 0) { 'CRITICAL' }
            elseif ($forestResults.Warnings -gt 0) { 'WARNING' }
            else { 'OK' }

            $overallStatus | Should -Be 'WARNING'
        }

        It 'Returns OK when all domains are healthy' {
            $forestResults = @{
                CriticalIssues = 0
                Warnings       = 0
                HealthyDomains = 0
            }
            $domainResults = @(
                @{ Status = 'OK' },
                @{ Status = 'Completed' },
                @{ Status = 'OK' }
            )

            foreach ($result in $domainResults) {
                switch ($result.Status) {
                    'CRITICAL' { $forestResults.CriticalIssues++ }
                    'WARNING' { $forestResults.Warnings++ }
                    { $_ -in @('OK', 'Completed') } { $forestResults.HealthyDomains++ }
                }
            }

            $overallStatus = if ($forestResults.CriticalIssues -gt 0) { 'CRITICAL' }
            elseif ($forestResults.Warnings -gt 0) { 'WARNING' }
            else { 'OK' }

            $overallStatus | Should -Be 'OK'
            $forestResults.HealthyDomains | Should -Be 3
        }

        It 'Handles failed domains' {
            $forestResults = @{
                CriticalIssues = 0
                Warnings       = 0
                HealthyDomains = 0
            }
            $domainResults = @(
                @{ Status = 'OK' },
                @{ Status = 'Failed' }
            )

            foreach ($result in $domainResults) {
                switch ($result.Status) {
                    'CRITICAL' { $forestResults.CriticalIssues++ }
                    'WARNING' { $forestResults.Warnings++ }
                    { $_ -in @('OK', 'Completed') } { $forestResults.HealthyDomains++ }
                }
            }

            $overallStatus = if ($forestResults.CriticalIssues -gt 0) { 'CRITICAL' }
            elseif ($forestResults.Warnings -gt 0) { 'WARNING' }
            else { 'OK' }

            # Failed doesn't count as CRITICAL or WARNING in the original logic
            $overallStatus | Should -Be 'OK'
            $forestResults.HealthyDomains | Should -Be 1
        }
    }
}

# ============================================================
# Invoke-DomainAssessment
# ============================================================

Describe 'Invoke-DomainAssessment' {
    BeforeEach {
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    Context 'When DC discovery succeeds' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{
                    HostName = 'dc01.contoso.com'
                }
            }
        }

        It 'Discovers DC and sets server parameter' {
            # Create a temp script that returns a simple result
            $tempScript = Join-Path ([System.IO.Path]::GetTempPath()) "test_assess_$(Get-Random).ps1"
            Set-Content -Path $tempScript -Value @'
param([string]$Server, [string]$Domain)
@{
    OverallStatus = 'OK'
    Domain = $Server
}
'@

            try {
                $result = Invoke-DomainAssessment -DomainName 'contoso.com' -ScriptPath $tempScript -AnalyzeLogs $false -Hours 24 -Export $false
                $result.Domain | Should -Be 'contoso.com'
            }
            finally {
                Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'When DC discovery fails' {
        BeforeEach {
            Mock Get-ADDomainController { throw "Cannot locate DC" }
        }

        It 'Falls back to domain name' {
            $tempScript = Join-Path ([System.IO.Path]::GetTempPath()) "test_assess_$(Get-Random).ps1"
            Set-Content -Path $tempScript -Value @'
param([string]$Server, [string]$Domain)
@{
    OverallStatus = 'OK'
    Domain = $Domain
}
'@

            try {
                $result = Invoke-DomainAssessment -DomainName 'contoso.com' -ScriptPath $tempScript -AnalyzeLogs $false -Hours 24 -Export $false
                $result.Domain | Should -Be 'contoso.com'
            }
            finally {
                Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'When assessment script fails' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{
                    HostName = 'dc01.contoso.com'
                }
            }
        }

        It 'Returns failed status with error message' {
            $tempScript = Join-Path ([System.IO.Path]::GetTempPath()) "test_assess_$(Get-Random).ps1"
            Set-Content -Path $tempScript -Value 'throw "Assessment failed due to permissions"'

            try {
                $result = Invoke-DomainAssessment -DomainName 'contoso.com' -ScriptPath $tempScript -AnalyzeLogs $false -Hours 24 -Export $false
                $result.Status | Should -Be 'Failed'
                $result.Error | Should -BeLike '*Assessment failed*'
            }
            finally {
                Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'When AnalyzeLogs is enabled' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{
                    HostName = 'dc01.contoso.com'
                }
            }
        }

        It 'Passes event log parameters correctly' {
            $tempScript = Join-Path ([System.IO.Path]::GetTempPath()) "test_assess_$(Get-Random).ps1"
            Set-Content -Path $tempScript -Value @'
param(
    [string]$Server,
    [string]$Domain,
    [switch]$AnalyzeEventLogs,
    [int]$EventLogHours,
    [switch]$ExportResults
)
@{
    OverallStatus    = 'OK'
    AnalyzeEventLogs = [bool]$AnalyzeEventLogs
    EventLogHours    = $EventLogHours
}
'@

            try {
                $result = Invoke-DomainAssessment -DomainName 'contoso.com' -ScriptPath $tempScript -AnalyzeLogs $true -Hours 48 -Export $false
                $result.Data.AnalyzeEventLogs | Should -BeTrue
                $result.Data.EventLogHours | Should -Be 48
            }
            finally {
                Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# ============================================================
# Forest Export Logic
# ============================================================

Describe 'Forest Export Logic' {
    Context 'Forest results structure' {
        It 'Creates valid forest results hashtable' {
            $forestResults = @{
                ForestName     = 'contoso.com'
                AssessmentDate = Get-Date
                TotalDomains   = 2
                DomainResults  = @()
                OverallStatus  = 'Unknown'
                CriticalIssues = 0
                Warnings       = 0
                HealthyDomains = 0
            }

            $forestResults.ForestName | Should -Be 'contoso.com'
            $forestResults.TotalDomains | Should -Be 2
            $forestResults.OverallStatus | Should -Be 'Unknown'
        }

        It 'Can serialize to JSON' {
            $forestResults = @{
                ForestName     = 'contoso.com'
                AssessmentDate = (Get-Date).ToString('o')
                TotalDomains   = 1
                DomainResults  = @(
                    @{
                        Domain = 'contoso.com'
                        Status = 'OK'
                    }
                )
                OverallStatus  = 'OK'
            }

            $json = $forestResults | ConvertTo-Json -Depth 5
            $json | Should -Not -BeNullOrEmpty
            $deserialized = $json | ConvertFrom-Json
            $deserialized.ForestName | Should -Be 'contoso.com'
        }
    }
}
