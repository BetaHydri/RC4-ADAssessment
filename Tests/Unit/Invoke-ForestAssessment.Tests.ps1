BeforeAll {
    $script:Version = '4.0.0'
    $script:AssessmentTimestamp = Get-Date

    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain { param([string]$Identity, [string]$Server, $ErrorAction) }
    }
    if (-not (Get-Command 'Get-ADForest' -ErrorAction SilentlyContinue)) {
        function global:Get-ADForest { param([string]$Identity, [string]$Server, $ErrorAction) }
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

Describe 'Invoke-RC4ForestAssessment' {
    BeforeEach {
        Mock -ModuleName 'RC4-ADAssessment' Write-Host {}
        Mock -ModuleName 'RC4-ADAssessment' Write-Warning {}
        Mock -ModuleName 'RC4-ADAssessment' Write-Error {}
        Mock -ModuleName 'RC4-ADAssessment' Get-ADForest {
            [PSCustomObject]@{
                Name    = 'contoso.com'
                RootDomain = 'contoso.com'
                ForestMode = 'Windows2016Forest'
                Domains = @('contoso.com')
            }
        }
        Mock -ModuleName 'RC4-ADAssessment' Get-ADDomain {
            [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
        }
        Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
            if ($Discover) {
                return [PSCustomObject]@{ HostName = 'dc01.contoso.com' }
            }
            return @()
        }
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
        Mock -ModuleName 'RC4-ADAssessment' Test-Path { $true }
    }

    It 'Has the Invoke-RC4ForestAssessment function available' {
        Get-Command Invoke-RC4ForestAssessment | Should -Not -BeNullOrEmpty
    }

    It 'Has the expected parameters' {
        $cmd = Get-Command Invoke-RC4ForestAssessment
        $cmd.Parameters.Keys | Should -Contain 'ForestName'
        $cmd.Parameters.Keys | Should -Contain 'AnalyzeEventLogs'
        $cmd.Parameters.Keys | Should -Contain 'ExportResults'
    }
}
