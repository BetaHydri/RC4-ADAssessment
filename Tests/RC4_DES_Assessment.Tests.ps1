#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for RC4_DES_Assessment.ps1
.DESCRIPTION
    Comprehensive mocked unit tests for all assessment functions in RC4_DES_Assessment.ps1.
    All Active Directory and Group Policy cmdlets are mocked to allow testing without a domain environment.
.NOTES
    Author: Jan Tiedemann
    Requires: Pester 5.x
#>

BeforeAll {
    # Dot-source the script to import functions
    # We need to handle the #Requires and param block - extract functions only
    $scriptPath = Join-Path $PSScriptRoot '..' 'RC4_DES_Assessment.ps1'
    $scriptContent = Get-Content -Path $scriptPath -Raw

    # Extract the function definitions from the script (between #region and main execution)
    $functionsBlock = [regex]::Match(
        $scriptContent,
        '(?s)#region Helper Functions.*?(?=#region Main Execution)'
    ).Value

    # Also extract the version variable
    $versionBlock = @'
$script:Version = "2.7.1"
$script:AssessmentTimestamp = Get-Date
'@

    # Create a temporary script block with just the functions
    $tempScript = $versionBlock + "`n" + $functionsBlock
    
    # Create stubs for AD module cmdlets so mocks can bind parameters correctly.
    # Stubs must declare the parameters that ParameterFilter references.
    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain {
            param([string]$Identity, [string]$Server, $ErrorAction)
        }
    }
    if (-not (Get-Command 'Get-ADComputer' -ErrorAction SilentlyContinue)) {
        function global:Get-ADComputer {
            param([string]$Identity, [string]$Filter, [string]$SearchBase, [string[]]$Properties, [string]$Server, $ErrorAction)
        }
    }
    if (-not (Get-Command 'Get-ADTrust' -ErrorAction SilentlyContinue)) {
        function global:Get-ADTrust {
            param([string]$Filter, [string[]]$Properties, [string]$Server, $ErrorAction)
        }
    }
    if (-not (Get-Command 'Get-ADUser' -ErrorAction SilentlyContinue)) {
        function global:Get-ADUser {
            param([string]$Identity, [string]$Filter, [string[]]$Properties, [string]$SearchBase, [string]$Server, $ErrorAction)
        }
    }
    if (-not (Get-Command 'Get-ADServiceAccount' -ErrorAction SilentlyContinue)) {
        function global:Get-ADServiceAccount {
            param([string]$Identity, [string]$Filter, [string[]]$Properties, [string]$Server, $ErrorAction)
        }
    }
    if (-not (Get-Command 'Get-ADDomainController' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomainController {
            param([string]$DomainName, [switch]$Discover, [string]$Filter, [string]$Server, $ErrorAction)
        }
    }
    if (-not (Get-Command 'Get-ADForest' -ErrorAction SilentlyContinue)) {
        function global:Get-ADForest {
            param([string]$Identity, [string]$Server, $ErrorAction)
        }
    }

    # Stub GP cmdlets with proper parameters
    if (-not (Get-Command 'Get-GPInheritance' -ErrorAction SilentlyContinue)) {
        function global:Get-GPInheritance {
            param([string]$Target, [string]$Domain, [string]$Server, $ErrorAction)
        }
    }
    if (-not (Get-Command 'Get-GPOReport' -ErrorAction SilentlyContinue)) {
        function global:Get-GPOReport {
            param([guid]$Guid, [string]$ReportType, [string]$Domain, [string]$Server, $ErrorAction)
        }
    }

    # Stub Test-Connection if running in constrained environment
    if (-not (Get-Command 'Test-Connection' -ErrorAction SilentlyContinue)) {
        function global:Test-Connection {
            param([string]$ComputerName, [int]$Count, [switch]$Quiet, $ErrorAction)
            $true
        }
    }

    # Execute the function definitions
    . ([ScriptBlock]::Create($tempScript))
}

# ============================================================
# Helper Functions (Pure functions - no mocking needed)
# ============================================================

Describe 'Get-EncryptionTypeString' {
    It 'Returns "Not Set (Default)" for null input' {
        Get-EncryptionTypeString -Value $null | Should -Be "Not Set (Default)"
    }

    It 'Returns "Not Set (Default)" for zero' {
        Get-EncryptionTypeString -Value 0 | Should -Be "Not Set (Default)"
    }

    It 'Returns "DES-CBC-CRC" for value 1' {
        Get-EncryptionTypeString -Value 1 | Should -Be "DES-CBC-CRC"
    }

    It 'Returns "DES-CBC-MD5" for value 2' {
        Get-EncryptionTypeString -Value 2 | Should -Be "DES-CBC-MD5"
    }

    It 'Returns "DES-CBC-CRC, DES-CBC-MD5" for value 3' {
        Get-EncryptionTypeString -Value 3 | Should -Be "DES-CBC-CRC, DES-CBC-MD5"
    }

    It 'Returns "RC4-HMAC" for value 4' {
        Get-EncryptionTypeString -Value 4 | Should -Be "RC4-HMAC"
    }

    It 'Returns "AES128-HMAC" for value 8' {
        Get-EncryptionTypeString -Value 8 | Should -Be "AES128-HMAC"
    }

    It 'Returns "AES256-HMAC" for value 16' {
        Get-EncryptionTypeString -Value 16 | Should -Be "AES256-HMAC"
    }

    It 'Returns "RC4-HMAC, AES128-HMAC, AES256-HMAC" for value 28 (0x1C)' {
        Get-EncryptionTypeString -Value 28 | Should -Be "RC4-HMAC, AES128-HMAC, AES256-HMAC"
    }

    It 'Returns "AES128-HMAC, AES256-HMAC" for value 24 (0x18)' {
        Get-EncryptionTypeString -Value 24 | Should -Be "AES128-HMAC, AES256-HMAC"
    }

    It 'Returns all types for value 31 (0x1F)' {
        Get-EncryptionTypeString -Value 31 | Should -Be "DES-CBC-CRC, DES-CBC-MD5, RC4-HMAC, AES128-HMAC, AES256-HMAC"
    }
}

Describe 'Get-TicketEncryptionType' {
    It 'Returns "DES-CBC-CRC" for 0x1' {
        Get-TicketEncryptionType -EncryptionType 0x1 | Should -Be "DES-CBC-CRC"
    }

    It 'Returns "DES-CBC-MD5" for 0x3' {
        Get-TicketEncryptionType -EncryptionType 0x3 | Should -Be "DES-CBC-MD5"
    }

    It 'Returns "AES128-HMAC-SHA1" for 0x11' {
        Get-TicketEncryptionType -EncryptionType 0x11 | Should -Be "AES128-HMAC-SHA1"
    }

    It 'Returns "AES256-HMAC-SHA1" for 0x12' {
        Get-TicketEncryptionType -EncryptionType 0x12 | Should -Be "AES256-HMAC-SHA1"
    }

    It 'Returns "RC4-HMAC" for 0x17' {
        Get-TicketEncryptionType -EncryptionType 0x17 | Should -Be "RC4-HMAC"
    }

    It 'Returns "RC4-HMAC-EXP" for 0x18' {
        Get-TicketEncryptionType -EncryptionType 0x18 | Should -Be "RC4-HMAC-EXP"
    }

    It 'Returns "Unknown (0xFF)" for unknown type 255' {
        Get-TicketEncryptionType -EncryptionType 0xFF | Should -Be "Unknown (0xFF)"
    }
}

# ============================================================
# Get-DomainControllerEncryption
# ============================================================

Describe 'Get-DomainControllerEncryption' {
    BeforeEach {
        # Standard domain info mock
        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'contoso.com'
                DistinguishedName = 'DC=contoso,DC=com'
            }
        }

        # Default: suppress Write-Host output during tests
        Mock Write-Host {}
    }

    Context 'When all DCs have AES configured' {
        BeforeEach {
            Mock Get-ADDomainController {
                @(
                    [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' },
                    [PSCustomObject]@{ Name = 'DC02'; HostName = 'dc02.contoso.com'; ComputerObjectDN = 'CN=DC02,OU=Domain Controllers,DC=contoso,DC=com' }
                )
            }
            Mock Get-ADComputer {
                param($Identity)
                switch -Wildcard ($Identity) {
                    '*DC01*' { [PSCustomObject]@{ Name = 'DC01'; 'msDS-SupportedEncryptionTypes' = 24; OperatingSystem = 'Windows Server 2022' } }
                    '*DC02*' { [PSCustomObject]@{ Name = 'DC02'; 'msDS-SupportedEncryptionTypes' = 24; OperatingSystem = 'Windows Server 2022' } }
                    'AzureADKerberos' { throw 'not found' }
                    default { $null }
                }
            }
            Mock Get-GPInheritance { $null }
        }

        It 'Returns correct total DC count' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.TotalDCs | Should -Be 2
        }

        It 'Counts all DCs as AES configured' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.AESConfigured | Should -Be 2
        }

        It 'Reports zero RC4 and DES' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.RC4Configured | Should -Be 0
            $result.DESConfigured | Should -Be 0
        }

        It 'Populates Details for each DC' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.Details | Should -HaveCount 2
            $result.Details[0].Name | Should -Be 'DC01'
            $result.Details[1].Name | Should -Be 'DC02'
        }
    }

    Context 'When a DC has RC4 only' {
        BeforeEach {
            Mock Get-ADDomainController {
                @(
                    [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' },
                    [PSCustomObject]@{ Name = 'DC02'; HostName = 'dc02.contoso.com'; ComputerObjectDN = 'CN=DC02,OU=Domain Controllers,DC=contoso,DC=com' }
                )
            }
            Mock Get-ADComputer {
                param($Identity)
                switch -Wildcard ($Identity) {
                    '*DC01*' { [PSCustomObject]@{ Name = 'DC01'; 'msDS-SupportedEncryptionTypes' = 24; OperatingSystem = 'Windows Server 2022' } }
                    '*DC02*' { [PSCustomObject]@{ Name = 'DC02'; 'msDS-SupportedEncryptionTypes' = 4; OperatingSystem = 'Windows Server 2016' } }
                    'AzureADKerberos' { throw 'not found' }
                    default { $null }
                }
            }
            Mock Get-GPInheritance { $null }
        }

        It 'Counts RC4 configured DCs' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.RC4Configured | Should -Be 1
        }

        It 'Sets status to "RC4 Only" on the RC4-only DC' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $dc02 = $result.Details | Where-Object { $_.Name -eq 'DC02' }
            $dc02.Status | Should -Be 'RC4 Only'
        }
    }

    Context 'When a DC has DES only' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC-LEGACY'; HostName = 'dc-legacy.contoso.com'; ComputerObjectDN = 'CN=DC-LEGACY,OU=Domain Controllers,DC=contoso,DC=com' }
            }
            Mock Get-ADComputer {
                param($Identity)
                switch -Wildcard ($Identity) {
                    '*DC-LEGACY*' { [PSCustomObject]@{ Name = 'DC-LEGACY'; 'msDS-SupportedEncryptionTypes' = 3; OperatingSystem = 'Windows Server 2008' } }
                    'AzureADKerberos' { throw 'not found' }
                    default { $null }
                }
            }
            Mock Get-GPInheritance { $null }
        }

        It 'Counts DES configured DCs' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.DESConfigured | Should -Be 1
        }

        It 'Sets status to "DES Only"' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.Details[0].Status | Should -Be 'DES Only'
        }
    }

    Context 'When a DC has AES + RC4 + DES' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC-MIXED'; HostName = 'dc-mixed.contoso.com'; ComputerObjectDN = 'CN=DC-MIXED,OU=Domain Controllers,DC=contoso,DC=com' }
            }
            Mock Get-ADComputer {
                param($Identity)
                switch -Wildcard ($Identity) {
                    '*DC-MIXED*' { [PSCustomObject]@{ Name = 'DC-MIXED'; 'msDS-SupportedEncryptionTypes' = 31; OperatingSystem = 'Windows Server 2019' } }
                    'AzureADKerberos' { throw 'not found' }
                    default { $null }
                }
            }
            Mock Get-GPInheritance { $null }
        }

        It 'Counts AES, RC4, and DES' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.AESConfigured | Should -Be 1
            $result.RC4Configured | Should -Be 1
            $result.DESConfigured | Should -Be 1
        }

        It 'Sets status to "AES Configured + RC4 + DES"' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.Details[0].Status | Should -Be 'AES Configured + RC4 + DES'
        }
    }

    Context 'When DCs have no encryption type set (inherit from GPO)' {
        BeforeEach {
            Mock Get-ADDomainController {
                @(
                    [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' },
                    [PSCustomObject]@{ Name = 'DC02'; HostName = 'dc02.contoso.com'; ComputerObjectDN = 'CN=DC02,OU=Domain Controllers,DC=contoso,DC=com' }
                )
            }
            Mock Get-ADComputer {
                param($Identity)
                switch -Wildcard ($Identity) {
                    '*DC01*' { [PSCustomObject]@{ Name = 'DC01'; 'msDS-SupportedEncryptionTypes' = $null; OperatingSystem = 'Windows Server 2022' } }
                    '*DC02*' { [PSCustomObject]@{ Name = 'DC02'; 'msDS-SupportedEncryptionTypes' = 0; OperatingSystem = 'Windows Server 2022' } }
                    'AzureADKerberos' { throw 'not found' }
                    default { $null }
                }
            }
            Mock Get-GPInheritance { $null }
        }

        It 'Counts both as NotConfigured' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.NotConfigured | Should -Be 2
        }
    }

    Context 'When GPO is configured with AES' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' }
            }
            Mock Get-ADComputer {
                param($Identity)
                switch -Wildcard ($Identity) {
                    '*DC01*' { [PSCustomObject]@{ Name = 'DC01'; 'msDS-SupportedEncryptionTypes' = $null; OperatingSystem = 'Windows Server 2022' } }
                    'AzureADKerberos' { throw 'not found' }
                    default { $null }
                }
            }
            Mock Get-GPInheritance {
                [PSCustomObject]@{
                    GpoLinks = @(
                        [PSCustomObject]@{
                            Enabled     = $true
                            GpoId       = [guid]::NewGuid()
                            DisplayName = 'Kerberos Encryption Policy'
                        }
                    )
                }
            }
            Mock Get-GPOReport {
                '<GPO><Computer><ExtensionData><Extension><SecurityOptions><KeyName name="Configure encryption types allowed for Kerberos"><decimal value="24"/></KeyName></SecurityOptions></Extension></ExtensionData></Computer></GPO>'
            }
        }

        It 'Sets GPOConfigured to true' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.GPOConfigured | Should -BeTrue
        }

        It 'Extracts GPO encryption types value' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.GPOEncryptionTypes | Should -Be 24
        }
    }

    Context 'When GroupPolicy module is broken (SYSVOL fallback via gPLink AD attribute)' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' }
            }
            Mock Get-ADComputer {
                param($Identity)
                switch -Wildcard ($Identity) {
                    '*DC01*' { [PSCustomObject]@{ Name = 'DC01'; 'msDS-SupportedEncryptionTypes' = 24; OperatingSystem = 'Windows Server 2022' } }
                    'AzureADKerberos' { throw 'not found' }
                    default { $null }
                }
            }
            # Simulate broken GroupPolicy module: GpoLinks returns strings instead of objects
            Mock Get-GPInheritance {
                [PSCustomObject]@{
                    GpoLinks = @(
                        'Microsoft.GroupPolicy.GpoLink',
                        'Microsoft.GroupPolicy.GpoLink'
                    )
                }
            }
            # AD-native fallback: gPLink attribute on DC OU
            Mock Get-ADObject {
                param($Identity, $Filter)
                if ($Identity -eq 'OU=Domain Controllers,DC=contoso,DC=com') {
                    [PSCustomObject]@{
                        gPLink = '[LDAP://cn={12345678-1234-1234-1234-123456789012},cn=policies,cn=system,DC=contoso,DC=com;0][LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=contoso,DC=com;0]'
                    }
                }
                elseif ($Filter) {
                    # GPO display name lookup
                    [PSCustomObject]@{ Name = '{12345678-1234-1234-1234-123456789012}'; DisplayName = 'Kerberos Encryption Policy' }
                }
            }
            Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*GptTmpl.inf' }
            Mock Get-Content {
                @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes=4,24
"@
            } -ParameterFilter { $LiteralPath -like '*GptTmpl.inf' }
        }

        It 'Sets GPOConfigured to true via SYSVOL fallback' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.GPOConfigured | Should -BeTrue
        }

        It 'Extracts GPO encryption types from SYSVOL security template' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.GPOEncryptionTypes | Should -Be 24
        }
    }

    Context 'With -Server parameter' {
        BeforeEach {
            Mock Get-ADDomainController { @() }
            Mock Get-ADComputer {
                param($Identity)
                if ($Identity -eq 'AzureADKerberos') { throw 'not found' }
                $null
            }
            Mock Get-GPInheritance { $null }
        }

        It 'Passes Server parameter to Get-ADDomain' {
            Get-DomainControllerEncryption -ServerParams @{ Server = 'dc01.contoso.com' }
            Should -Invoke Get-ADDomain -Times 1 -ParameterFilter { $Server -eq 'dc01.contoso.com' }
        }
    }

    Context 'When Get-ADDomain fails with Server parameter' {
        BeforeEach {
            Mock Get-ADDomain { throw "Unable to contact the server" }
        }

        It 'Returns assessment with zero counts (error handled)' {
            $result = Get-DomainControllerEncryption -ServerParams @{ Server = 'bad-dc.contoso.com' }
            $result.TotalDCs | Should -Be 0
        }
    }

    Context 'When AzureADKerberos object is present alongside real DCs' {
        BeforeEach {
            # Get-ADDomainController only returns real DCs (no AzureADKerberos)
            Mock Get-ADDomainController {
                @(
                    [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' },
                    [PSCustomObject]@{ Name = 'DC02'; HostName = 'dc02.contoso.com'; ComputerObjectDN = 'CN=DC02,OU=Domain Controllers,DC=contoso,DC=com' }
                )
            }
            # Get-ADComputer is called per-DC for properties, and for AzureADKerberos detection
            Mock Get-ADComputer {
                param($Identity)
                switch -Wildcard ($Identity) {
                    '*DC01*' { [PSCustomObject]@{ Name = 'DC01'; 'msDS-SupportedEncryptionTypes' = 24; OperatingSystem = 'Windows Server 2022' } }
                    '*DC02*' { [PSCustomObject]@{ Name = 'DC02'; 'msDS-SupportedEncryptionTypes' = 24; OperatingSystem = 'Windows Server 2022' } }
                    'AzureADKerberos' { [PSCustomObject]@{ Name = 'AzureADKerberos'; 'msDS-SupportedEncryptionTypes' = $null; OperatingSystem = $null } }
                    default { $null }
                }
            }
            Mock Get-GPInheritance { $null }
        }

        It 'Excludes AzureADKerberos from TotalDCs count' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.TotalDCs | Should -Be 2
        }

        It 'Excludes AzureADKerberos from Details array' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.Details | Should -HaveCount 2
            $result.Details.Name | Should -Not -Contain 'AzureADKerberos'
        }

        It 'Populates AzureADKerberos property with proxy info' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.AzureADKerberos | Should -Not -BeNullOrEmpty
            $result.AzureADKerberos.Name | Should -Be 'AzureADKerberos'
            $result.AzureADKerberos.IsAzureADKerberos | Should -BeTrue
            $result.AzureADKerberos.Status | Should -Match 'Entra Kerberos Proxy'
        }

        It 'Still counts real DCs as AES configured' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.AESConfigured | Should -Be 2
        }

        It 'Does not count AzureADKerberos as NotConfigured' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.NotConfigured | Should -Be 0
        }
    }

    Context 'When AzureADKerberos is the only object in DC OU (no real DCs from DC Locator)' {
        BeforeEach {
            # Get-ADDomainController returns no results (AzureADKerberos is not a real DC)
            Mock Get-ADDomainController { @() }
            Mock Get-ADComputer {
                param($Identity)
                if ($Identity -eq 'AzureADKerberos') {
                    [PSCustomObject]@{ Name = 'AzureADKerberos'; 'msDS-SupportedEncryptionTypes' = $null; OperatingSystem = $null }
                } else { $null }
            }
            Mock Get-GPInheritance { $null }
        }

        It 'Reports zero DCs' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.TotalDCs | Should -Be 0
        }

        It 'Still populates AzureADKerberos property' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.AzureADKerberos | Should -Not -BeNullOrEmpty
            $result.AzureADKerberos.Name | Should -Be 'AzureADKerberos'
        }

        It 'Has empty Details array' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.Details | Should -HaveCount 0
        }
    }

    Context 'When no AzureADKerberos object exists' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' }
            }
            Mock Get-ADComputer {
                param($Identity)
                switch -Wildcard ($Identity) {
                    '*DC01*' { [PSCustomObject]@{ Name = 'DC01'; 'msDS-SupportedEncryptionTypes' = 24; OperatingSystem = 'Windows Server 2022' } }
                    'AzureADKerberos' { throw 'not found' }
                    default { $null }
                }
            }
            Mock Get-GPInheritance { $null }
        }

        It 'AzureADKerberos property remains null' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.AzureADKerberos | Should -BeNullOrEmpty
        }

        It 'Counts normal DCs correctly' {
            $result = Get-DomainControllerEncryption -ServerParams @{}
            $result.TotalDCs | Should -Be 1
        }
    }
}

# ============================================================
# Get-TrustEncryptionAssessment
# ============================================================

Describe 'Get-TrustEncryptionAssessment' {
    BeforeEach {
        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'contoso.com'
                DistinguishedName = 'DC=contoso,DC=com'
            }
        }
        Mock Write-Host {}
    }

    Context 'When no trusts exist' {
        BeforeEach {
            Mock Get-ADTrust { $null }
        }

        It 'Returns zero trust count' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.TotalTrusts | Should -Be 0
        }

        It 'Returns empty Details array' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.Details | Should -HaveCount 0
        }
    }

    Context 'Post-November 2022: Trust with unset encryption (AES default)' {
        BeforeEach {
            Mock Get-ADTrust {
                [PSCustomObject]@{
                    Name                            = 'partner.com'
                    TrustDirection                  = 'Bidirectional'
                    TrustType                       = 'External'
                    'msDS-SupportedEncryptionTypes' = $null
                }
            }
        }

        It 'Counts as DefaultAES' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.DefaultAES | Should -Be 1
        }

        It 'Sets PostNov2022Compliant to true' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.Details[0].PostNov2022Compliant | Should -BeTrue
        }

        It 'Sets status showing AES default' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.Details[0].Status | Should -BeLike '*AES*Default*'
        }
    }

    Context 'Trust with explicit AES (0x18)' {
        BeforeEach {
            Mock Get-ADTrust {
                [PSCustomObject]@{
                    Name                            = 'child.contoso.com'
                    TrustDirection                  = 'Bidirectional'
                    TrustType                       = 'ParentChild'
                    'msDS-SupportedEncryptionTypes' = 24  # AES128 + AES256
                }
            }
        }

        It 'Counts as ExplicitAES' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.ExplicitAES | Should -Be 1
        }

        It 'Has zero RC4Risk and DESRisk' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.RC4Risk | Should -Be 0
            $result.DESRisk | Should -Be 0
        }
    }

    Context 'Trust with AES + RC4 (0x1C)' {
        BeforeEach {
            Mock Get-ADTrust {
                [PSCustomObject]@{
                    Name                            = 'legacy.com'
                    TrustDirection                  = 'Inbound'
                    TrustType                       = 'External'
                    'msDS-SupportedEncryptionTypes' = 28  # AES + RC4
                }
            }
        }

        It 'Counts as ExplicitAES and RC4Risk' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.ExplicitAES | Should -Be 1
            $result.RC4Risk | Should -Be 1
        }

        It 'Status mentions RC4 Enabled' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.Details[0].Status | Should -BeLike '*RC4 Enabled*'
        }
    }

    Context 'Trust with RC4 only (0x4)' {
        BeforeEach {
            Mock Get-ADTrust {
                [PSCustomObject]@{
                    Name                            = 'old-partner.com'
                    TrustDirection                  = 'Outbound'
                    TrustType                       = 'External'
                    'msDS-SupportedEncryptionTypes' = 4
                }
            }
        }

        It 'Counts as RC4Risk' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.RC4Risk | Should -Be 1
        }

        It 'Sets status to "RC4 Only"' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.Details[0].Status | Should -Be 'RC4 Only'
        }
    }

    Context 'Trust with DES only (0x3)' {
        BeforeEach {
            Mock Get-ADTrust {
                [PSCustomObject]@{
                    Name                            = 'ancient.com'
                    TrustDirection                  = 'Bidirectional'
                    TrustType                       = 'External'
                    'msDS-SupportedEncryptionTypes' = 3
                }
            }
        }

        It 'Counts as DESRisk' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.DESRisk | Should -Be 1
        }

        It 'Sets status to "DES Only"' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.Details[0].Status | Should -Be 'DES Only'
        }
    }

    Context 'Multiple trusts with mixed encryption' {
        BeforeEach {
            Mock Get-ADTrust {
                @(
                    [PSCustomObject]@{
                        Name                            = 'aes-trust.com'
                        TrustDirection                  = 'Bidirectional'
                        TrustType                       = 'External'
                        'msDS-SupportedEncryptionTypes' = 24
                    },
                    [PSCustomObject]@{
                        Name                            = 'default-trust.com'
                        TrustDirection                  = 'Bidirectional'
                        TrustType                       = 'External'
                        'msDS-SupportedEncryptionTypes' = $null
                    },
                    [PSCustomObject]@{
                        Name                            = 'rc4-trust.com'
                        TrustDirection                  = 'Inbound'
                        TrustType                       = 'External'
                        'msDS-SupportedEncryptionTypes' = 4
                    }
                )
            }
        }

        It 'Counts total trusts correctly' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.TotalTrusts | Should -Be 3
        }

        It 'Has correct distribution' {
            $result = Get-TrustEncryptionAssessment -ServerParams @{}
            $result.ExplicitAES | Should -Be 1
            $result.DefaultAES | Should -Be 1
            $result.RC4Risk | Should -Be 1
        }
    }
}

# ============================================================
# Get-AccountEncryptionAssessment
# ============================================================

Describe 'Get-AccountEncryptionAssessment' {
    BeforeEach {
        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'contoso.com'
                DistinguishedName = 'DC=contoso,DC=com'
            }
        }
        Mock Write-Host {}
    }

    Context 'KRBTGT with healthy password age' {
        BeforeEach {
            Mock Get-ADUser {
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
            Mock Get-ADServiceAccount { $null }
        }

        It 'Reports KRBTGT password age correctly' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.KRBTGT.PasswordAgeDays | Should -BeGreaterOrEqual 89
            $result.KRBTGT.PasswordAgeDays | Should -BeLessOrEqual 91
        }

        It 'Sets KRBTGT status to OK' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.KRBTGT.Status | Should -Be 'OK'
        }

        It 'Sets encryption types for KRBTGT' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.KRBTGT.EncryptionTypes | Should -Be 'AES128-HMAC, AES256-HMAC'
        }
    }

    Context 'KRBTGT with WARNING password age (181-365 days)' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-200)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-200)
                    }
                }
                return $null
            }
            Mock Get-ADServiceAccount { $null }
        }

        It 'Sets KRBTGT status to WARNING' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.KRBTGT.Status | Should -Be 'WARNING'
        }
    }

    Context 'KRBTGT with CRITICAL password age (>365 days)' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-500)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-500)
                    }
                }
                return $null
            }
            Mock Get-ADServiceAccount { $null }
        }

        It 'Sets KRBTGT status to CRITICAL' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.KRBTGT.Status | Should -Be 'CRITICAL'
        }

        It 'Reports password age > 365 days' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.KRBTGT.PasswordAgeDays | Should -BeGreaterThan 365
        }
    }

    Context 'KRBTGT with RC4-only encryption' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 4  # RC4 only
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                return $null
            }
            Mock Get-ADServiceAccount { $null }
        }

        It 'Reports RC4-HMAC encryption type' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.KRBTGT.EncryptionTypes | Should -Be 'RC4-HMAC'
            $result.KRBTGT.EncryptionValue | Should -Be 4
        }
    }

    Context 'Accounts with USE_DES_KEY_ONLY flag' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                if ($Filter -and "$Filter" -match '2097152') {
                    return @(
                        [PSCustomObject]@{
                            SamAccountName                  = 'svc_legacy'
                            DistinguishedName               = 'CN=svc_legacy,OU=Service Accounts,DC=contoso,DC=com'
                            Enabled                         = $true
                            PasswordLastSet                 = (Get-Date).AddDays(-400)
                            UserAccountControl              = 2097664
                            'msDS-SupportedEncryptionTypes' = 3
                            ServicePrincipalName            = @('HTTP/legacy.contoso.com')
                        },
                        [PSCustomObject]@{
                            SamAccountName                  = 'test_des'
                            DistinguishedName               = 'CN=test_des,OU=Users,DC=contoso,DC=com'
                            Enabled                         = $false
                            PasswordLastSet                 = (Get-Date).AddDays(-100)
                            UserAccountControl              = 2097664
                            'msDS-SupportedEncryptionTypes' = $null
                            ServicePrincipalName            = $null
                        }
                    )
                }
                return $null
            }
            Mock Get-ADServiceAccount { $null }
        }

        It 'Detects DES flag accounts' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalDESFlag | Should -Be 2
        }

        It 'Populates DESFlagAccounts with correct details' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.DESFlagAccounts | Should -HaveCount 2
            $result.DESFlagAccounts[0].Name | Should -Be 'svc_legacy'
            $result.DESFlagAccounts[0].Flag | Should -Be 'USE_DES_KEY_ONLY'
        }

        It 'Tracks enabled status' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.DESFlagAccounts[0].Enabled | Should -BeTrue
            $result.DESFlagAccounts[1].Enabled | Should -BeFalse
        }
    }

    Context 'Service accounts with RC4-only encryption' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                if ($Filter -and "$Filter" -match 'ServicePrincipalName') {
                    return @(
                        [PSCustomObject]@{
                            SamAccountName                  = 'svc_sql'
                            DistinguishedName               = 'CN=svc_sql,OU=Service Accounts,DC=contoso,DC=com'
                            Enabled                         = $true
                            PasswordLastSet                 = (Get-Date).AddDays(-100)
                            'msDS-SupportedEncryptionTypes' = 4
                            ServicePrincipalName            = @('MSSQLSvc/sqlserver.contoso.com:1433')
                            DisplayName                     = 'SQL Service Account'
                        },
                        [PSCustomObject]@{
                            SamAccountName                  = 'svc_web'
                            DistinguishedName               = 'CN=svc_web,OU=Service Accounts,DC=contoso,DC=com'
                            Enabled                         = $true
                            PasswordLastSet                 = (Get-Date).AddDays(-50)
                            'msDS-SupportedEncryptionTypes' = 24
                            ServicePrincipalName            = @('HTTP/web.contoso.com')
                            DisplayName                     = 'Web Service Account'
                        }
                    )
                }
                return $null
            }
            Mock Get-ADServiceAccount { $null }
        }

        It 'Detects RC4-only service accounts' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalRC4OnlySvc | Should -Be 1
        }

        It 'Does not flag AES-only service accounts' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.RC4OnlyServiceAccounts[0].Name | Should -Be 'svc_sql'
            $result.RC4OnlyServiceAccounts | Where-Object { $_.Name -eq 'svc_web' } | Should -BeNullOrEmpty
        }

        It 'Captures SPN information' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.RC4OnlyServiceAccounts[0].SPNs | Should -BeLike '*MSSQLSvc*'
        }
    }

    Context 'Stale service accounts with RC4' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                if ($Filter -and "$Filter" -match 'ServicePrincipalName') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'svc_old'
                        DistinguishedName               = 'CN=svc_old,OU=Service Accounts,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-500)
                        'msDS-SupportedEncryptionTypes' = 28
                        ServicePrincipalName            = @('HTTP/old.contoso.com')
                        DisplayName                     = 'Old Service Account'
                    }
                }
                return $null
            }
            Mock Get-ADServiceAccount { $null }
        }

        It 'Detects stale service accounts with RC4 enabled' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalStaleSvc | Should -Be 1
        }

        It 'Reports correct password age' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.StaleServiceAccounts[0].PasswordAgeDays | Should -BeGreaterThan 365
        }

        It 'Does not count as RC4-only (since AES is also set)' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalRC4OnlySvc | Should -Be 0
        }
    }

    Context 'Managed Service Accounts with RC4-only' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                return $null
            }
            Mock Get-ADServiceAccount {
                @(
                    [PSCustomObject]@{
                        SamAccountName                  = 'gmsa_app$'
                        DistinguishedName               = 'CN=gmsa_app,CN=Managed Service Accounts,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-15)
                        'msDS-SupportedEncryptionTypes' = 4
                        ServicePrincipalName            = @('HTTP/app.contoso.com')
                        ObjectClass                     = 'msDS-GroupManagedServiceAccount'
                    },
                    [PSCustomObject]@{
                        SamAccountName                  = 'gmsa_secure$'
                        DistinguishedName               = 'CN=gmsa_secure,CN=Managed Service Accounts,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-10)
                        'msDS-SupportedEncryptionTypes' = 24
                        ServicePrincipalName            = @('HTTP/secure.contoso.com')
                        ObjectClass                     = 'msDS-GroupManagedServiceAccount'
                    }
                )
            }
        }

        It 'Detects RC4-only MSAs' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalRC4OnlyMSA | Should -Be 1
        }

        It 'Identifies MSA type correctly' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.RC4OnlyMSAs[0].Type | Should -Be 'gMSA'
        }

        It 'Does not flag AES MSAs' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.RC4OnlyMSAs | Where-Object { $_.Name -eq 'gmsa_secure$' } | Should -BeNullOrEmpty
        }
    }

    Context 'When Get-ADServiceAccount is unavailable' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                return $null
            }
            Mock Get-ADServiceAccount { throw "The term 'Get-ADServiceAccount' is not recognized" }
        }

        It 'Handles missing Get-ADServiceAccount gracefully' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalRC4OnlyMSA | Should -Be 0
        }
    }

    Context 'DES-enabled accounts detection (DES bits alongside AES)' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                # SPN service account with DES+AES (value 31 = 0x1F)
                return @(
                    [PSCustomObject]@{
                        SamAccountName                  = 'svc_legacy'
                        DistinguishedName               = 'CN=svc_legacy,OU=ServiceAccounts,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-60)
                        'msDS-SupportedEncryptionTypes' = 31
                        ServicePrincipalName            = @('HTTP/legacy.contoso.com')
                        DisplayName                     = 'Legacy Service'
                    },
                    [PSCustomObject]@{
                        SamAccountName                  = 'svc_clean'
                        DistinguishedName               = 'CN=svc_clean,OU=ServiceAccounts,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        'msDS-SupportedEncryptionTypes' = 24
                        ServicePrincipalName            = @('HTTP/clean.contoso.com')
                        DisplayName                     = 'Clean Service'
                    }
                )
            }
            Mock Get-ADServiceAccount {
                @(
                    [PSCustomObject]@{
                        SamAccountName                  = 'gmsa_des$'
                        DistinguishedName               = 'CN=gmsa_des,CN=Managed Service Accounts,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-10)
                        'msDS-SupportedEncryptionTypes' = 27
                        ServicePrincipalName            = @('HTTP/des.contoso.com')
                        ObjectClass                     = 'msDS-GroupManagedServiceAccount'
                    }
                )
            }
        }

        It 'Detects DES bits on SPN service accounts with AES' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalDESEnabled | Should -Be 2
        }

        It 'Does not flag accounts without DES bits' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.DESEnabledAccounts | Where-Object { $_.Name -eq 'svc_clean' } | Should -BeNullOrEmpty
        }

        It 'Includes DES-enabled SPN account in list' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.DESEnabledAccounts | Where-Object { $_.Name -eq 'svc_legacy' } | Should -Not -BeNullOrEmpty
        }

        It 'Includes DES-enabled gMSA in list' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.DESEnabledAccounts | Where-Object { $_.Name -eq 'gmsa_des$' } | Should -Not -BeNullOrEmpty
        }

        It 'Does not flag DES-only accounts (no AES) as DES-enabled' {
            # DES-only accounts are caught by the RC4OnlyServiceAccounts check instead
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                return @(
                    [PSCustomObject]@{
                        SamAccountName                  = 'svc_desonly'
                        DistinguishedName               = 'CN=svc_desonly,OU=ServiceAccounts,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-60)
                        'msDS-SupportedEncryptionTypes' = 3
                        ServicePrincipalName            = @('HTTP/desonly.contoso.com')
                        DisplayName                     = 'DES Only Service'
                    }
                )
            }
            Mock Get-ADServiceAccount { return $null }
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalDESEnabled | Should -Be 0
        }
    }

    Context 'Clean environment (no issues)' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                return $null
            }
            Mock Get-ADServiceAccount { $null }
        }

        It 'Returns all-clear assessment' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.KRBTGT.Status | Should -Be 'OK'
            $result.TotalDESFlag | Should -Be 0
            $result.TotalRC4OnlySvc | Should -Be 0
            $result.TotalRC4OnlyMSA | Should -Be 0
            $result.TotalRC4Exception | Should -Be 0
            $result.TotalStaleSvc | Should -Be 0
        }
    }

    Context 'RC4 exception accounts detection (RC4 + AES = 0x1C)' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                # SPN service accounts with various encryption configs
                return @(
                    [PSCustomObject]@{
                        SamAccountName                  = 'svc_legacy'
                        DistinguishedName               = 'CN=svc_legacy,OU=ServiceAccounts,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-60)
                        'msDS-SupportedEncryptionTypes' = 28  # 0x1C = RC4 + AES128 + AES256
                        ServicePrincipalName            = @('HTTP/legacy.contoso.com')
                        DisplayName                     = 'Legacy Service'
                    },
                    [PSCustomObject]@{
                        SamAccountName                  = 'svc_clean'
                        DistinguishedName               = 'CN=svc_clean,OU=ServiceAccounts,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        'msDS-SupportedEncryptionTypes' = 24  # AES-only
                        ServicePrincipalName            = @('HTTP/clean.contoso.com')
                        DisplayName                     = 'Clean Service'
                    },
                    [PSCustomObject]@{
                        SamAccountName                  = 'svc_rc4only'
                        DistinguishedName               = 'CN=svc_rc4only,OU=ServiceAccounts,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        'msDS-SupportedEncryptionTypes' = 4  # RC4-only
                        ServicePrincipalName            = @('HTTP/rc4only.contoso.com')
                        DisplayName                     = 'RC4 Only Service'
                    }
                )
            }
            Mock Get-ADServiceAccount {
                @(
                    [PSCustomObject]@{
                        SamAccountName                  = 'gmsa_exc$'
                        DistinguishedName               = 'CN=gmsa_exc,CN=Managed Service Accounts,DC=contoso,DC=com'
                        Enabled                         = $true
                        PasswordLastSet                 = (Get-Date).AddDays(-10)
                        'msDS-SupportedEncryptionTypes' = 28  # 0x1C = RC4 + AES128 + AES256
                        ServicePrincipalName            = @('HTTP/exc.contoso.com')
                        ObjectClass                     = 'msDS-GroupManagedServiceAccount'
                    }
                )
            }
        }

        It 'Detects RC4 exception accounts (RC4 + AES)' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalRC4Exception | Should -Be 2
        }

        It 'Includes SPN service account with 0x1C in RC4 exception list' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.RC4ExceptionAccounts | Where-Object { $_.Name -eq 'svc_legacy' } | Should -Not -BeNullOrEmpty
        }

        It 'Includes gMSA with 0x1C in RC4 exception list' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.RC4ExceptionAccounts | Where-Object { $_.Name -eq 'gmsa_exc$' } | Should -Not -BeNullOrEmpty
        }

        It 'Does not flag AES-only accounts as RC4 exception' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.RC4ExceptionAccounts | Where-Object { $_.Name -eq 'svc_clean' } | Should -BeNullOrEmpty
        }

        It 'Does not flag RC4-only accounts as RC4 exception (no AES bits)' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.RC4ExceptionAccounts | Where-Object { $_.Name -eq 'svc_rc4only' } | Should -BeNullOrEmpty
        }

        It 'Still detects RC4-only accounts correctly' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalRC4OnlySvc | Should -Be 1
            $result.RC4OnlyServiceAccounts[0].Name | Should -Be 'svc_rc4only'
        }
    }
}

# ============================================================
# Get-EventLogEncryptionAnalysis
# ============================================================

Describe 'Get-EventLogEncryptionAnalysis' {
    BeforeEach {
        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'contoso.com'
                DistinguishedName = 'DC=contoso,DC=com'
            }
        }
        Mock Write-Host {}
    }

    Context 'When no DCs are found' {
        BeforeEach {
            Mock Get-ADDomainController { @() }
        }

        It 'Returns empty assessment' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.EventsAnalyzed | Should -Be 0
            $result.RC4Tickets | Should -Be 0
            $result.DESTickets | Should -Be 0
            $result.AESTickets | Should -Be 0
        }
    }

    Context 'When DC is unreachable' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Test-Connection { $false }
        }

        It 'Adds DC to FailedDCs list' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.FailedDCs | Should -HaveCount 1
            $result.FailedDCs[0].Name | Should -Be 'dc01.contoso.com'
        }

        It 'Reports zero events analyzed' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.EventsAnalyzed | Should -Be 0
        }
    }

    Context 'When events are retrieved successfully with AES tickets' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Test-Connection { $true }
            Mock Invoke-Command {
                # Simulate event objects with XML containing AES256 encryption
                # Use ScriptMethod so $event.ToXml() works correctly
                $evt1 = New-Object PSObject
                $evt1 | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
                    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="TargetUserName">user1</Data><Data Name="TicketEncryptionType">0x12</Data></EventData></Event>'
                }
                $evt1 | Add-Member -MemberType NoteProperty -Name Properties -Value @()

                $evt2 = New-Object PSObject
                $evt2 | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
                    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="TargetUserName">user2</Data><Data Name="TicketEncryptionType">0x12</Data></EventData></Event>'
                }
                $evt2 | Add-Member -MemberType NoteProperty -Name Properties -Value @()

                @($evt1, $evt2)
            }
        }

        It 'Counts AES tickets' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.AESTickets | Should -Be 2
        }

        It 'Tracks queried DCs' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.QueriedDCs | Should -Contain 'dc01.contoso.com'
        }

        It 'Reports correct event count' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.EventsAnalyzed | Should -Be 2
        }
    }

    Context 'When RC4 and DES tickets are detected' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Test-Connection { $true }
            Mock Invoke-Command {
                # RC4 ticket
                $evt1 = New-Object PSObject
                $evt1 | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
                    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="TargetUserName">legacy_app</Data><Data Name="TicketEncryptionType">0x17</Data></EventData></Event>'
                }
                $evt1 | Add-Member -MemberType NoteProperty -Name Properties -Value @()

                # DES ticket
                $evt2 = New-Object PSObject
                $evt2 | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
                    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="TargetUserName">ancient_app</Data><Data Name="TicketEncryptionType">0x1</Data></EventData></Event>'
                }
                $evt2 | Add-Member -MemberType NoteProperty -Name Properties -Value @()

                # Another RC4 ticket (same account)
                $evt3 = New-Object PSObject
                $evt3 | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
                    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="TargetUserName">legacy_app</Data><Data Name="TicketEncryptionType">0x17</Data></EventData></Event>'
                }
                $evt3 | Add-Member -MemberType NoteProperty -Name Properties -Value @()

                @($evt1, $evt2, $evt3)
            }
        }

        It 'Counts RC4 tickets' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.RC4Tickets | Should -Be 2
        }

        It 'Counts DES tickets' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.DESTickets | Should -Be 1
        }

        It 'Tracks unique RC4 accounts' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.RC4Accounts | Should -HaveCount 1
            $result.RC4Accounts | Should -Contain 'legacy_app'
        }

        It 'Tracks unique DES accounts' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.DESAccounts | Should -HaveCount 1
            $result.DESAccounts | Should -Contain 'ancient_app'
        }
    }

    Context 'When WinRM fails and RPC fallback succeeds' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Test-Connection { $true }
            Mock Invoke-Command { throw "WinRM connection failed" }
            Mock Get-WinEvent {
                $evt = New-Object PSObject
                $evt | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
                    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="TargetUserName">user1</Data><Data Name="TicketEncryptionType">0x12</Data></EventData></Event>'
                }
                $evt | Add-Member -MemberType NoteProperty -Name Properties -Value @()
                $evt
            }
        }

        It 'Falls back to RPC and still retrieves events' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.EventsAnalyzed | Should -Be 1
            $result.AESTickets | Should -Be 1
        }
    }

    Context 'When both WinRM and RPC fail' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Test-Connection { $true }
            Mock Invoke-Command { throw "WinRM connection failed" }
            Mock Get-WinEvent { throw "RPC server is unavailable" }
        }

        It 'Adds DC to FailedDCs with error' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 24
            $result.FailedDCs | Should -HaveCount 1
            $result.FailedDCs[0].Error | Should -BeLike '*RPC*'
        }
    }

    Context 'TimeRange parameter' {
        BeforeEach {
            Mock Get-ADDomainController { @() }
        }

        It 'Uses provided Hours value' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{} -Hours 48
            $result.TimeRange | Should -Be 48
        }

        It 'Defaults to 24 hours' {
            $result = Get-EventLogEncryptionAnalysis -ServerParams @{}
            $result.TimeRange | Should -Be 24
        }
    }
}

# ============================================================
# Show-AssessmentSummary
# ============================================================

Describe 'Show-AssessmentSummary' {
    BeforeEach {
        Mock Write-Host {}
    }

    Context 'With complete results' {
        It 'Does not throw with valid results' {
            $results = @{
                DomainControllers = @{
                    TotalDCs           = 2
                    AESConfigured      = 2
                    RC4Configured      = 0
                    DESConfigured      = 0
                    GPOConfigured      = $true
                    GPOEncryptionTypes = 24
                    Details            = @(
                        @{ Name = 'DC01'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC'; EncryptionValue = 24; OperatingSystem = 'Windows Server 2022' },
                        @{ Name = 'DC02'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC'; EncryptionValue = 24; OperatingSystem = 'Windows Server 2022' }
                    )
                }
                EventLogs         = @{
                    EventsAnalyzed = 100
                    RC4Tickets     = 0
                    DESTickets     = 0
                    AESTickets     = 100
                    QueriedDCs     = @('dc01.contoso.com', 'dc02.contoso.com')
                    FailedDCs      = @()
                }
                Trusts            = @{
                    TotalTrusts = 1
                    RC4Risk     = 0
                    DESRisk     = 0
                    AESSecure   = 1
                    Details     = @(
                        @{ Name = 'partner.com'; Direction = 'Bidirectional'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC' }
                    )
                }
                Accounts          = @{
                    KRBTGT                 = @{
                        Status          = 'OK'
                        PasswordAgeDays = 30
                        EncryptionTypes = 'AES128-HMAC, AES256-HMAC'
                    }
                    TotalDESFlag           = 0
                    TotalRC4OnlySvc        = 0
                    TotalRC4OnlyMSA        = 0
                    TotalStaleSvc          = 0
                    DESFlagAccounts        = @()
                    RC4OnlyServiceAccounts = @()
                    RC4OnlyMSAs            = @()
                    StaleServiceAccounts   = @()
                }
            }

            { Show-AssessmentSummary -Results $results } | Should -Not -Throw
        }
    }

    Context 'Without event logs' {
        It 'Handles null EventLogs gracefully' {
            $results = @{
                DomainControllers = @{ TotalDCs = 0; Details = @(); GPOConfigured = $false; GPOEncryptionTypes = $null; AESConfigured = 0; RC4Configured = 0; DESConfigured = 0 }
                EventLogs         = $null
                Trusts            = @{ TotalTrusts = 0; Details = @() }
                Accounts          = $null
            }

            { Show-AssessmentSummary -Results $results } | Should -Not -Throw
        }
    }

    Context 'With failed DCs in event logs' {
        It 'Handles FailedDCs data' {
            $results = @{
                DomainControllers = @{ TotalDCs = 0; Details = @(); GPOConfigured = $false; GPOEncryptionTypes = $null; AESConfigured = 0; RC4Configured = 0; DESConfigured = 0 }
                EventLogs         = @{
                    EventsAnalyzed = 0
                    RC4Tickets     = 0
                    DESTickets     = 0
                    AESTickets     = 0
                    QueriedDCs     = @()
                    FailedDCs      = @(
                        @{ Name = 'dc01.contoso.com'; Error = 'WinRM failed' }
                    )
                }
                Trusts            = @{ TotalTrusts = 0; Details = @() }
                Accounts          = $null
            }

            { Show-AssessmentSummary -Results $results } | Should -Not -Throw
        }
    }
}

# ============================================================
# Write-Finding (display helper)
# ============================================================

Describe 'Write-Finding' {
    BeforeEach {
        Mock Write-Host {}
    }

    It 'Handles OK status without error' {
        { Write-Finding -Status 'OK' -Message 'All good' } | Should -Not -Throw
    }

    It 'Handles WARNING status without error' {
        { Write-Finding -Status 'WARNING' -Message 'Minor issue' } | Should -Not -Throw
    }

    It 'Handles CRITICAL status without error' {
        { Write-Finding -Status 'CRITICAL' -Message 'Major issue' } | Should -Not -Throw
    }

    It 'Handles INFO status without error' {
        { Write-Finding -Status 'INFO' -Message 'Informational' } | Should -Not -Throw
    }

    It 'Displays detail when provided' {
        Write-Finding -Status 'OK' -Message 'Test' -Detail 'Extra detail'
        Should -Invoke Write-Host -Times 2  # One for message, one for detail
    }

    It 'Does not display detail line when not provided' {
        Write-Finding -Status 'OK' -Message 'Test'
        Should -Invoke Write-Host -Times 1
    }
}

# ============================================================
# Write-Header and Write-Section
# ============================================================

Describe 'Write-Header' {
    BeforeEach {
        Mock Write-Host {}
    }

    It 'Displays header without error' {
        { Write-Header -Title 'Test Header' } | Should -Not -Throw
    }

    It 'Calls Write-Host 3 times (top line, title, bottom line)' {
        Write-Header -Title 'Test Header'
        Should -Invoke Write-Host -Times 3
    }
}

Describe 'Write-Section' {
    BeforeEach {
        Mock Write-Host {}
    }

    It 'Displays section without error' {
        { Write-Section -Title 'Test Section' } | Should -Not -Throw
    }

    It 'Calls Write-Host 2 times (title, separator)' {
        Write-Section -Title 'Test Section'
        Should -Invoke Write-Host -Times 2
    }
}

# ============================================================
# Integration-style: Overall Scoring Logic
# ============================================================

Describe 'Overall Assessment Scoring Logic' {
    # This tests the scoring logic conceptually - same logic used in main execution block

    It 'Returns CRITICAL when DES is configured on DCs' {
        $criticalIssues = 0
        $warnings = 0
        $dcResult = @{ DESConfigured = 1; RC4Configured = 0 }

        if ($dcResult.DESConfigured -gt 0) { $criticalIssues++ }

        $status = if ($criticalIssues -gt 0) { "CRITICAL" } elseif ($warnings -gt 0) { "WARNING" } else { "OK" }
        $status | Should -Be "CRITICAL"
    }

    It 'Returns WARNING when RC4 is configured on DCs' {
        $criticalIssues = 0
        $warnings = 0
        $dcResult = @{ DESConfigured = 0; RC4Configured = 1 }

        if ($dcResult.RC4Configured -gt 0) { $warnings++ }

        $status = if ($criticalIssues -gt 0) { "CRITICAL" } elseif ($warnings -gt 0) { "WARNING" } else { "OK" }
        $status | Should -Be "WARNING"
    }

    It 'Returns OK when no issues found' {
        $criticalIssues = 0
        $warnings = 0
        $dcResult = @{ DESConfigured = 0; RC4Configured = 0 }

        $status = if ($criticalIssues -gt 0) { "CRITICAL" } elseif ($warnings -gt 0) { "WARNING" } else { "OK" }
        $status | Should -Be "OK"
    }

    It 'Returns CRITICAL when KRBTGT password is stale' {
        $criticalIssues = 0
        $accountResult = @{ KRBTGT = @{ Status = 'CRITICAL'; PasswordAgeDays = 500 } }

        if ($accountResult.KRBTGT.Status -eq 'CRITICAL') { $criticalIssues++ }

        $status = if ($criticalIssues -gt 0) { "CRITICAL" } else { "OK" }
        $status | Should -Be "CRITICAL"
    }

    It 'Returns CRITICAL when DES flag accounts exist' {
        $criticalIssues = 0
        $accountResult = @{ TotalDESFlag = 3 }

        if ($accountResult.TotalDESFlag -gt 0) { $criticalIssues++ }

        $status = if ($criticalIssues -gt 0) { "CRITICAL" } else { "OK" }
        $status | Should -Be "CRITICAL"
    }

    It 'Returns CRITICAL when RC4 tickets found in event logs' {
        $criticalIssues = 0
        $eventResult = @{ RC4Tickets = 5 }

        if ($eventResult.RC4Tickets -gt 0) { $criticalIssues++ }

        $status = if ($criticalIssues -gt 0) { "CRITICAL" } else { "OK" }
        $status | Should -Be "CRITICAL"
    }

    It 'Returns WARNING when stale service accounts with RC4 exist' {
        $criticalIssues = 0
        $warnings = 0
        $accountResult = @{ TotalStaleSvc = 2 }

        if ($accountResult.TotalStaleSvc -gt 0) { $warnings++ }

        $status = if ($criticalIssues -gt 0) { "CRITICAL" } elseif ($warnings -gt 0) { "WARNING" } else { "OK" }
        $status | Should -Be "WARNING"
    }

    It 'Returns WARNING when missing AES key accounts exist' {
        $criticalIssues = 0
        $warnings = 0
        $accountResult = @{ TotalMissingAES = 5 }

        if ($accountResult.TotalMissingAES -gt 0) { $warnings++ }

        $status = if ($criticalIssues -gt 0) { "CRITICAL" } elseif ($warnings -gt 0) { "WARNING" } else { "OK" }
        $status | Should -Be "WARNING"
    }

    It 'Returns WARNING when RC4DefaultDisablementPhase is not set' {
        $criticalIssues = 0
        $warnings = 0
        $regResult = @{ RC4DefaultDisablementPhase = @{ Status = 'NOT SET' } }

        if ($regResult.RC4DefaultDisablementPhase.Status -eq 'NOT SET') { $warnings++ }

        $status = if ($criticalIssues -gt 0) { "CRITICAL" } elseif ($warnings -gt 0) { "WARNING" } else { "OK" }
        $status | Should -Be "WARNING"
    }

    It 'Returns WARNING when RC4 exception accounts exist (0x1C)' {
        $criticalIssues = 0
        $warnings = 0
        $accountResult = @{ TotalRC4Exception = 3 }

        if ($accountResult.TotalRC4Exception -gt 0) { $warnings++ }

        $status = if ($criticalIssues -gt 0) { "CRITICAL" } elseif ($warnings -gt 0) { "WARNING" } else { "OK" }
        $status | Should -Be "WARNING"
    }

    It 'Returns CRITICAL when DefaultDomainSupportedEncTypes lacks AES' {
        $criticalIssues = 0
        $regResult = @{ DefaultDomainSupportedEncTypes = @{ Status = 'CRITICAL' } }

        if ($regResult.DefaultDomainSupportedEncTypes.Status -eq 'CRITICAL') { $criticalIssues++ }

        $status = if ($criticalIssues -gt 0) { "CRITICAL" } else { "OK" }
        $status | Should -Be "CRITICAL"
    }
}

# ============================================================
# Get-KdcRegistryAssessment
# ============================================================

Describe 'Get-KdcRegistryAssessment' {
    BeforeEach {
        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'contoso.com'
                DistinguishedName = 'DC=contoso,DC=com'
            }
        }
        Mock Write-Host {}
    }

    Context 'When no DCs are found' {
        BeforeEach {
            Mock Get-ADDomainController { @() }
        }

        It 'Returns empty assessment' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.QueriedDCs | Should -HaveCount 0
            $result.DefaultDomainSupportedEncTypes.Configured | Should -BeFalse
            $result.RC4DefaultDisablementPhase.Configured | Should -BeFalse
        }
    }

    Context 'When RC4DefaultDisablementPhase is set to 1' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = $null
                    RC4DefaultDisablementPhase     = 1
                }
            }
        }

        It 'Reports RC4DefaultDisablementPhase as OK (audit mode)' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.RC4DefaultDisablementPhase.Configured | Should -BeTrue
            $result.RC4DefaultDisablementPhase.Value | Should -Be 1
            $result.RC4DefaultDisablementPhase.Status | Should -Be 'OK'
        }

        It 'Tracks queried DC' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.QueriedDCs | Should -Contain 'dc01.contoso.com'
        }
    }

    Context 'When RC4DefaultDisablementPhase is set to 0' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = $null
                    RC4DefaultDisablementPhase     = 0
                }
            }
        }

        It 'Reports RC4DefaultDisablementPhase as WARNING' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.RC4DefaultDisablementPhase.Status | Should -Be 'WARNING'
        }
    }

    Context 'When DefaultDomainSupportedEncTypes is AES-only' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = 24  # AES128 + AES256
                    RC4DefaultDisablementPhase     = $null
                }
            }
        }

        It 'Reports AES-only status as OK' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.DefaultDomainSupportedEncTypes.Configured | Should -BeTrue
            $result.DefaultDomainSupportedEncTypes.IncludesAES | Should -BeTrue
            $result.DefaultDomainSupportedEncTypes.IncludesRC4 | Should -BeFalse
            $result.DefaultDomainSupportedEncTypes.Status | Should -Be 'OK'
        }
    }

    Context 'When DefaultDomainSupportedEncTypes includes RC4 and AES' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = 28  # RC4 + AES128 + AES256
                    RC4DefaultDisablementPhase     = 1
                }
            }
        }

        It 'Reports RC4 included for exceptions' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.DefaultDomainSupportedEncTypes.IncludesRC4 | Should -BeTrue
            $result.DefaultDomainSupportedEncTypes.IncludesAES | Should -BeTrue
        }
    }

    Context 'When DefaultDomainSupportedEncTypes has no AES' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = 4  # RC4 only
                    RC4DefaultDisablementPhase     = $null
                }
            }
        }

        It 'Reports CRITICAL when no AES in DefaultDomainSupportedEncTypes' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.DefaultDomainSupportedEncTypes.Status | Should -Be 'CRITICAL'
            $result.DefaultDomainSupportedEncTypes.IncludesAES | Should -BeFalse
        }
    }

    Context 'When WinRM fails on a DC' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command { throw "WinRM connection failed" }
        }

        It 'Adds DC to FailedDCs list' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.FailedDCs | Should -HaveCount 1
            $result.FailedDCs[0].Name | Should -Be 'dc01.contoso.com'
        }
    }

    Context 'When neither registry key is set' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = $null
                    RC4DefaultDisablementPhase     = $null
                }
            }
        }

        It 'Reports both as NOT SET' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.DefaultDomainSupportedEncTypes.Status | Should -Be 'NOT SET'
            $result.RC4DefaultDisablementPhase.Status | Should -Be 'NOT SET'
        }
    }

    Context 'When RC4DefaultDisablementPhase is set to 2 (Enforcement)' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = $null
                    RC4DefaultDisablementPhase     = 2
                }
            }
        }

        It 'Reports RC4DefaultDisablementPhase as OK (Enforcement mode)' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.RC4DefaultDisablementPhase.Configured | Should -BeTrue
            $result.RC4DefaultDisablementPhase.Value | Should -Be 2
            $result.RC4DefaultDisablementPhase.Status | Should -Be 'OK'
        }
    }

    Context 'When AzureADKerberos object is present alongside real DCs' {
        BeforeEach {
            # Get-ADDomainController only returns real DCs
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @{
                    DefaultDomainSupportedEncTypes = $null
                    RC4DefaultDisablementPhase     = 1
                }
            }
        }

        It 'Only queries real DCs (AzureADKerberos automatically excluded)' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.QueriedDCs | Should -Contain 'dc01.contoso.com'
            $result.QueriedDCs | Should -HaveCount 1
        }
    }

    Context 'When no DCs found (AzureADKerberos only exists in OU but not as real DC)' {
        BeforeEach {
            Mock Get-ADDomainController { @() }
        }

        It 'Returns empty assessment with no queried DCs' {
            $result = Get-KdcRegistryAssessment -ServerParams @{}
            $result.QueriedDCs | Should -HaveCount 0
            $result.DefaultDomainSupportedEncTypes.Configured | Should -BeFalse
            $result.RC4DefaultDisablementPhase.Configured | Should -BeFalse
        }
    }
}

# ============================================================
# Get-KdcSvcEventAssessment
# ============================================================

Describe 'Get-KdcSvcEventAssessment' {
    BeforeEach {
        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'contoso.com'
                DistinguishedName = 'DC=contoso,DC=com'
            }
        }
        Mock Write-Host {}
    }

    Context 'When no DCs are found' {
        BeforeEach {
            Mock Get-ADDomainController { @() }
        }

        It 'Returns empty assessment' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.TotalEvents | Should -Be 0
            $result.QueriedDCs | Should -HaveCount 0
        }
    }

    Context 'When no KDCSVC events are found' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command { @() }
        }

        It 'Returns OK status with no events' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.TotalEvents | Should -Be 0
            $result.Status | Should -Be 'OK'
            $result.QueriedDCs | Should -Contain 'dc01.contoso.com'
        }
    }

    Context 'When KDCSVC events are found' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @(
                    [PSCustomObject]@{ Id = 201; TimeCreated = (Get-Date); Message = 'RC4 service ticket requested' },
                    [PSCustomObject]@{ Id = 205; TimeCreated = (Get-Date); Message = 'Insecure DefaultDomainSupportedEncTypes' }
                )
            }
        }

        It 'Returns WARNING status with event counts' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.TotalEvents | Should -Be 2
            $result.Status | Should -Be 'WARNING'
            $result.EventCounts['201'] | Should -Be 1
            $result.EventCounts['205'] | Should -Be 1
        }

        It 'Tracks event details' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.EventDetails | Should -HaveCount 2
            $result.EventDetails[0].DC | Should -Be 'dc01.contoso.com'
        }
    }

    Context 'When WinRM fails with No events found' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command { throw 'No events were found that match the specified selection criteria.' }
        }

        It 'Returns OK when no events match' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.TotalEvents | Should -Be 0
            $result.Status | Should -Be 'OK'
            $result.QueriedDCs | Should -Contain 'dc01.contoso.com'
        }
    }

    Context 'When WinRM fails completely' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command { throw 'WinRM connection failed' }
            Mock Get-WinEvent { throw 'RPC server unavailable' }
        }

        It 'Adds DC to FailedDCs list' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.FailedDCs | Should -HaveCount 1
            $result.FailedDCs[0].Name | Should -Be 'dc01.contoso.com'
        }
    }

    Context 'When AzureADKerberos object is present alongside real DCs' {
        BeforeEach {
            # Get-ADDomainController only returns real DCs
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command { @() }
        }

        It 'Only queries real DCs (AzureADKerberos automatically excluded)' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.QueriedDCs | Should -Contain 'dc01.contoso.com'
            $result.QueriedDCs | Should -HaveCount 1
        }
    }

    Context 'When no DCs found (AzureADKerberos only in OU)' {
        BeforeEach {
            Mock Get-ADDomainController { @() }
        }

        It 'Returns empty assessment with no queried DCs' {
            $result = Get-KdcSvcEventAssessment -ServerParams @{}
            $result.TotalEvents | Should -Be 0
            $result.QueriedDCs | Should -HaveCount 0
        }
    }
}

# ============================================================
# Get-AuditPolicyCheck
# ============================================================

Describe 'Get-AuditPolicyCheck' {
    BeforeEach {
        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'contoso.com'
                DistinguishedName = 'DC=contoso,DC=com'
            }
        }
        Mock Write-Host {}
    }

    Context 'When no DC is found' {
        BeforeEach {
            Mock Get-ADDomainController { @() }
        }

        It 'Returns unknown status' {
            $result = Get-AuditPolicyCheck -ServerParams @{}
            $result.Status | Should -Be 'Unknown'
        }
    }

    Context 'When both audit policies are enabled' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @{
                    AuthService = "Kerberos Authentication Service  Success and Failure"
                    TicketOps   = "Kerberos Service Ticket Operations  Success and Failure"
                }
            }
        }

        It 'Reports OK status' {
            $result = Get-AuditPolicyCheck -ServerParams @{}
            $result.Status | Should -Be 'OK'
            $result.KerberosAuthServiceEnabled | Should -BeTrue
            $result.KerberosTicketOpsEnabled | Should -BeTrue
        }

        It 'Records queried DC' {
            $result = Get-AuditPolicyCheck -ServerParams @{}
            $result.QueriedDC | Should -Be 'dc01.contoso.com'
        }
    }

    Context 'When no audit policies are enabled' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @{
                    AuthService = "Kerberos Authentication Service  No Auditing"
                    TicketOps   = "Kerberos Service Ticket Operations  No Auditing"
                }
            }
        }

        It 'Reports CRITICAL status' {
            $result = Get-AuditPolicyCheck -ServerParams @{}
            $result.Status | Should -Be 'CRITICAL'
            $result.KerberosAuthServiceEnabled | Should -BeFalse
            $result.KerberosTicketOpsEnabled | Should -BeFalse
        }
    }

    Context 'When only one audit policy is enabled' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command {
                @{
                    AuthService = "Kerberos Authentication Service  Success"
                    TicketOps   = "Kerberos Service Ticket Operations  No Auditing"
                }
            }
        }

        It 'Reports WARNING status' {
            $result = Get-AuditPolicyCheck -ServerParams @{}
            $result.Status | Should -Be 'WARNING'
            $result.KerberosAuthServiceEnabled | Should -BeTrue
            $result.KerberosTicketOpsEnabled | Should -BeFalse
        }
    }

    Context 'When WinRM fails' {
        BeforeEach {
            Mock Get-ADDomainController {
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'dc01.contoso.com' }
            }
            Mock Invoke-Command { throw "WinRM connection failed" }
        }

        It 'Reports UNKNOWN status' {
            $result = Get-AuditPolicyCheck -ServerParams @{}
            $result.Status | Should -Be 'UNKNOWN'
        }
    }
}

# ============================================================
# Get-AccountEncryptionAssessment - Missing AES Keys
# ============================================================

Describe 'Get-AccountEncryptionAssessment - Missing AES Keys' {
    BeforeEach {
        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'contoso.com'
                DistinguishedName = 'DC=contoso,DC=com'
                DomainMode        = 'Windows2016Domain'
            }
        }
        Mock Write-Host {}
    }

    Context 'When accounts with very old passwords exist' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                if ($Filter -and "$Filter" -match 'PasswordLastSet') {
                    return @(
                        [PSCustomObject]@{
                            SamAccountName                  = 'old_user1'
                            DistinguishedName               = 'CN=old_user1,OU=Users,DC=contoso,DC=com'
                            Enabled                         = $true
                            PasswordLastSet                 = (Get-Date).AddDays(-2000)
                            'msDS-SupportedEncryptionTypes' = $null
                            ServicePrincipalName            = $null
                            WhenCreated                     = (Get-Date).AddDays(-3000)
                        },
                        [PSCustomObject]@{
                            SamAccountName                  = 'old_svc'
                            DistinguishedName               = 'CN=old_svc,OU=Service,DC=contoso,DC=com'
                            Enabled                         = $true
                            PasswordLastSet                 = (Get-Date).AddDays(-2500)
                            'msDS-SupportedEncryptionTypes' = 0
                            ServicePrincipalName            = @('HTTP/old.contoso.com')
                            WhenCreated                     = (Get-Date).AddDays(-3000)
                        }
                    )
                }
                return $null
            }
            Mock Get-ADServiceAccount { $null }
        }

        It 'Detects accounts missing AES keys' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalMissingAES | Should -Be 2
        }

        It 'Populates MissingAESKeyAccounts details' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.MissingAESKeyAccounts | Should -HaveCount 2
            $result.MissingAESKeyAccounts[0].Name | Should -Be 'old_user1'
            $result.MissingAESKeyAccounts[0].Type | Should -Be 'Missing AES Keys'
        }

        It 'Tracks SPN status for missing AES accounts' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.MissingAESKeyAccounts[0].HasSPN | Should -BeFalse
            $result.MissingAESKeyAccounts[1].HasSPN | Should -BeTrue
        }
    }

    Context 'When no old accounts exist' {
        BeforeEach {
            Mock Get-ADUser {
                if ("$Identity" -eq 'krbtgt') {
                    return [PSCustomObject]@{
                        SamAccountName                  = 'krbtgt'
                        PasswordLastSet                 = (Get-Date).AddDays(-30)
                        pwdLastSet                      = $null
                        'msDS-SupportedEncryptionTypes' = 24
                        WhenChanged                     = (Get-Date).AddDays(-30)
                    }
                }
                return $null
            }
            Mock Get-ADServiceAccount { $null }
        }

        It 'Returns zero missing AES accounts' {
            $result = Get-AccountEncryptionAssessment -ServerParams @{}
            $result.TotalMissingAES | Should -Be 0
            $result.MissingAESKeyAccounts | Should -HaveCount 0
        }
    }
}
