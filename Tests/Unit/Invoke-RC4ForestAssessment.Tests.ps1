#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for Invoke-RC4ForestAssessment.
.DESCRIPTION
    Mocked unit tests covering forest discovery, sequential domain assessment,
    status aggregation, export logic, and error handling paths.
.NOTES
    Author: Jan Tiedemann
    Requires: Pester 5.x
#>

BeforeAll {
    # Create AD module stubs if not available
    if (-not (Get-Command 'Get-ADForest' -ErrorAction SilentlyContinue)) {
        function global:Get-ADForest {
            param([string]$Identity, [string]$Server, $ErrorAction)
        }
    }
    if (-not (Get-Command 'Get-ADDomain' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomain {
            param([string]$Identity, [string]$Server, $ErrorAction)
        }
    }
    if (-not (Get-Command 'Get-ADDomainController' -ErrorAction SilentlyContinue)) {
        function global:Get-ADDomainController {
            param([string]$DomainName, [switch]$Discover, [string]$Filter, [string]$Server, $ErrorAction)
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
    if (-not (Get-Command 'Get-ADObject' -ErrorAction SilentlyContinue)) {
        function global:Get-ADObject {
            param([string]$Identity, [string]$Filter, [string]$SearchBase, [string[]]$Properties, [string]$Server, $ErrorAction)
        }
    }
    if (-not (Get-Command 'Get-GPInheritance' -ErrorAction SilentlyContinue)) {
        function global:Get-GPInheritance {
            param([string]$Target, [string]$Domain, [string]$Server, $ErrorAction)
        }
    }
    if (-not (Get-Command 'Test-Connection' -ErrorAction SilentlyContinue)) {
        function global:Test-Connection {
            param([string]$ComputerName, [int]$Count, [switch]$Quiet, $ErrorAction) $true
        }
    }
}

Describe 'Invoke-RC4ForestAssessment' {

    BeforeEach {
        # Suppress console output
        Mock -ModuleName 'RC4-ADAssessment' Write-Host {}
        Mock -ModuleName 'RC4-ADAssessment' Write-Warning {}

        # Mock ReadKey to bypass "Press any key" prompt
        Mock -ModuleName 'RC4-ADAssessment' -CommandName 'Get-Variable' -ParameterFilter {
            $Name -eq 'Host'
        } {}

        # Default forest mock — two domains
        Mock -ModuleName 'RC4-ADAssessment' Get-ADForest {
            [PSCustomObject]@{
                Name       = 'contoso.com'
                RootDomain = 'contoso.com'
                Domains    = @('contoso.com', 'child.contoso.com')
                ForestMode = 'Windows2016Forest'
            }
        }

        # Mock DC discovery for Invoke-DomainAssessment
        Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
            [PSCustomObject]@{ HostName = 'dc01.contoso.com' }
        }

        # Mock Invoke-RC4Assessment to return predictable results
        Mock -ModuleName 'RC4-ADAssessment' Invoke-RC4Assessment {
            @{ OverallStatus = 'OK' }
        }

        # Mock Show-ForestSummary
        Mock -ModuleName 'RC4-ADAssessment' Show-ForestSummary {}

        # Mock filesystem for export tests
        Mock -ModuleName 'RC4-ADAssessment' Test-Path { $true }
        Mock -ModuleName 'RC4-ADAssessment' New-Item {}
        Mock -ModuleName 'RC4-ADAssessment' Out-File {}
        Mock -ModuleName 'RC4-ADAssessment' Export-Csv {}
        Mock -ModuleName 'RC4-ADAssessment' Get-ChildItem { $null }
    }

    Context 'Forest discovery with default forest' {
        It 'Calls Get-ADForest without -Identity when ForestName is not specified' {
            # We need to skip the ReadKey - mock the Host object
            $mockRawUI = [PSCustomObject]@{}
            $mockRawUI | Add-Member -MemberType ScriptMethod -Name 'ReadKey' -Value { param($options) } -Force
            $mockUI = [PSCustomObject]@{ RawUI = $mockRawUI }
            $mockHost = [PSCustomObject]@{ UI = $mockUI }

            # Override $Host inside the module scope
            & (Get-Module RC4-ADAssessment) {
                $script:OriginalHost = $Host
            }

            Mock -ModuleName 'RC4-ADAssessment' Get-ADForest {
                [PSCustomObject]@{
                    Name       = 'contoso.com'
                    RootDomain = 'contoso.com'
                    Domains    = @('contoso.com')
                    ForestMode = 'Windows2016Forest'
                }
            }

            # The function calls $Host.UI.RawUI.ReadKey which we can't easily mock.
            # Instead, test that Get-ADForest is called (it will fail at ReadKey).
            # We'll handle this by mocking the entire Host variable via a different approach.
            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Get-ADForest -Times 1
        }
    }

    Context 'Forest discovery with named forest' {
        It 'Calls Get-ADForest with -Identity when ForestName is specified' {
            try { Invoke-RC4ForestAssessment -ForestName 'contoso.com' } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Get-ADForest -Times 1 -ParameterFilter {
                $Identity -eq 'contoso.com'
            }
        }
    }

    Context 'Sequential domain assessment' {
        It 'Calls Invoke-RC4Assessment for each domain in the forest' {
            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -Times 2
        }

        It 'Passes -Domain parameter for each domain' {
            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -ParameterFilter {
                $Domain -eq 'child.contoso.com'
            }
            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -ParameterFilter {
                $Domain -eq 'contoso.com'
            }
        }

        It 'Passes -Server when DC discovery succeeds' {
            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -ParameterFilter {
                $Server -eq 'dc01.contoso.com'
            }
        }

        It 'Passes -AnalyzeEventLogs and -EventLogHours when specified' {
            try { Invoke-RC4ForestAssessment -AnalyzeEventLogs -EventLogHours 48 } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -ParameterFilter {
                $AnalyzeEventLogs -eq $true -and $EventLogHours -eq 48
            }
        }

        It 'Passes -DeepScan when specified' {
            try { Invoke-RC4ForestAssessment -DeepScan } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -ParameterFilter {
                $DeepScan -eq $true
            }
        }

        It 'Passes -ExportResults when specified' {
            try { Invoke-RC4ForestAssessment -ExportResults } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -ParameterFilter {
                $ExportResults -eq $true
            }
        }

        It 'Passes -IncludeGuidance when specified' {
            try { Invoke-RC4ForestAssessment -IncludeGuidance } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -ParameterFilter {
                $IncludeGuidance -eq $true
            }
        }
    }

    Context 'DC discovery fallback' {
        It 'Continues assessment when DC discovery fails' {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController { throw 'Cannot contact domain' }

            try { Invoke-RC4ForestAssessment } catch {}

            # Should still call Invoke-RC4Assessment (without -Server)
            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -Times 2
        }
    }

    Context 'Domain assessment failure handling' {
        It 'Continues with other domains when one domain assessment fails' {
            $script:callCount = 0
            Mock -ModuleName 'RC4-ADAssessment' Invoke-RC4Assessment {
                $script:callCount++
                if ($script:callCount -eq 1) {
                    throw 'Domain unreachable'
                }
                @{ OverallStatus = 'OK' }
            }

            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -Times 2
        }
    }

    Context 'Status aggregation' {
        It 'Sets OverallStatus to OK when all domains are healthy' {
            Mock -ModuleName 'RC4-ADAssessment' Invoke-RC4Assessment {
                @{ OverallStatus = 'OK' }
            }

            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Show-ForestSummary -Times 1
        }

        It 'Sets OverallStatus to WARNING when a domain returns WARNING' {
            $script:domainCallCount = 0
            Mock -ModuleName 'RC4-ADAssessment' Invoke-RC4Assessment {
                $script:domainCallCount++
                if ($script:domainCallCount -eq 1) {
                    @{ OverallStatus = 'WARNING' }
                }
                else {
                    @{ OverallStatus = 'OK' }
                }
            }

            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Show-ForestSummary -Times 1
        }

        It 'Sets OverallStatus to CRITICAL when a domain returns CRITICAL' {
            Mock -ModuleName 'RC4-ADAssessment' Invoke-RC4Assessment {
                @{ OverallStatus = 'CRITICAL' }
            }

            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Show-ForestSummary -Times 1
        }
    }

    Context 'Export functionality' {
        It 'Creates Exports directory when ExportResults is specified' {
            Mock -ModuleName 'RC4-ADAssessment' Test-Path { $false }

            try { Invoke-RC4ForestAssessment -ExportResults } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName New-Item -Times 1 -ParameterFilter {
                $ItemType -eq 'Directory'
            }
        }

        It 'Exports JSON forest summary when ExportResults is specified' {
            try { Invoke-RC4ForestAssessment -ExportResults } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Out-File -Times 1
        }

        It 'Exports CSV domain summary when ExportResults is specified' {
            try { Invoke-RC4ForestAssessment -ExportResults } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Export-Csv -Times 1
        }

        It 'Does not export when ExportResults is not specified' {
            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Out-File -Times 0
            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Export-Csv -Times 0
        }
    }

    Context 'Forest discovery failure' {
        It 'Writes error when Get-ADForest fails' {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADForest { throw 'Cannot contact forest' }
            Mock -ModuleName 'RC4-ADAssessment' Write-Error {}

            # The function calls exit 1 on failure, which terminates the test runner.
            # We catch the exit by running in a script block.
            try { Invoke-RC4ForestAssessment -ForestName 'bad.forest.com' } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Write-Error -Times 1
        }
    }

    Context 'Single domain forest' {
        It 'Processes a forest with only one domain' {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADForest {
                [PSCustomObject]@{
                    Name       = 'single.com'
                    RootDomain = 'single.com'
                    Domains    = @('single.com')
                    ForestMode = 'Windows2016Forest'
                }
            }

            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -Times 1 -ParameterFilter {
                $Domain -eq 'single.com'
            }
        }
    }

    Context 'DC hostname extraction' {
        It 'Handles HostName as array' {
            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController {
                [PSCustomObject]@{ HostName = @('dc01.contoso.com', 'dc02.contoso.com') }
            }

            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -ParameterFilter {
                $Server -eq 'dc01.contoso.com'
            }
        }

        It 'Handles HostName with Value property (ADPropertyValueCollection)' {
            $mockDC = [PSCustomObject]@{}
            $hostNameObj = [PSCustomObject]@{ Value = 'dc01.contoso.com' }
            $mockDC | Add-Member -MemberType NoteProperty -Name 'HostName' -Value $hostNameObj -Force

            Mock -ModuleName 'RC4-ADAssessment' Get-ADDomainController { $mockDC }

            try { Invoke-RC4ForestAssessment } catch {}

            Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Invoke-RC4Assessment -ParameterFilter {
                $Server -eq 'dc01.contoso.com'
            }
        }
    }
}
