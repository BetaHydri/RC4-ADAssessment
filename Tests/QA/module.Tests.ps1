#Requires -Modules Pester

<#
.SYNOPSIS
    Quality assurance tests for the RC4ADCheck module.
.DESCRIPTION
    Tests module manifest, function exports, and basic code quality.
.NOTES
    Requires: Pester 5.x
#>

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $sourceRoot = Join-Path -Path $projectRoot -ChildPath 'source'
    $manifestPath = Join-Path -Path $sourceRoot -ChildPath 'RC4ADCheck.psd1'
}

Describe 'Module Manifest' -Tag 'QA' {
    It 'Has a valid module manifest' {
        $manifestPath | Should -Exist
    }

    It 'Manifest passes Test-ModuleManifest' {
        { Test-ModuleManifest -Path $manifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'Has a valid root module' {
        $manifest = Test-ModuleManifest -Path $manifestPath
        $manifest.RootModule | Should -Be 'RC4ADCheck.psm1'
    }

    It 'Has a valid GUID' {
        $manifest = Test-ModuleManifest -Path $manifestPath
        $manifest.Guid | Should -Not -BeNullOrEmpty
    }

    It 'Has a description' {
        $manifest = Test-ModuleManifest -Path $manifestPath
        $manifest.Description | Should -Not -BeNullOrEmpty
    }

    It 'Has an author' {
        $manifest = Test-ModuleManifest -Path $manifestPath
        $manifest.Author | Should -Not -BeNullOrEmpty
    }

    It 'Has project URI' {
        $manifest = Test-ModuleManifest -Path $manifestPath
        $manifest.PrivateData.PSData.ProjectUri | Should -Not -BeNullOrEmpty
    }

    It 'Has license URI' {
        $manifest = Test-ModuleManifest -Path $manifestPath
        $manifest.PrivateData.PSData.LicenseUri | Should -Not -BeNullOrEmpty
    }

    It 'Requires PowerShell 5.1 or later' {
        $manifest = Test-ModuleManifest -Path $manifestPath
        $manifest.PowerShellVersion | Should -Be '5.1'
    }
}

Describe 'Module Function Exports' -Tag 'QA' {
    BeforeAll {
        $manifest = Test-ModuleManifest -Path $manifestPath
        $publicFunctions = Get-ChildItem -Path (Join-Path $sourceRoot 'Public') -Filter '*.ps1' -Recurse |
            Select-Object -ExpandProperty BaseName
    }

    It 'Exports all public functions' {
        foreach ($function in $publicFunctions) {
            $manifest.ExportedFunctions.Keys | Should -Contain $function `
                -Because "$function is in source/Public/ and should be exported"
        }
    }

    It 'Does not export private functions' {
        $privateFunctions = Get-ChildItem -Path (Join-Path $sourceRoot 'Private') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty BaseName

        foreach ($function in $privateFunctions) {
            $manifest.ExportedFunctions.Keys | Should -Not -Contain $function `
                -Because "$function is in source/Private/ and should not be exported"
        }
    }

    It 'Does not export variables' {
        $manifest.ExportedVariables.Count | Should -Be 0
    }

    It 'Does not export cmdlets' {
        $manifest.ExportedCmdlets.Count | Should -Be 0
    }
}

Describe 'Source File Quality' -Tag 'QA' {
    BeforeAll {
        $allSourceFiles = Get-ChildItem -Path $sourceRoot -Filter '*.ps1' -Recurse
    }

    It 'Each public function file contains exactly one function matching the filename' {
        $publicFiles = Get-ChildItem -Path (Join-Path $sourceRoot 'Public') -Filter '*.ps1'
        foreach ($file in $publicFiles) {
            $content = Get-Content -Path $file.FullName -Raw
            $functionMatches = [regex]::Matches($content, '(?m)^function\s+(\S+)')
            $functionMatches.Count | Should -BeGreaterOrEqual 1 `
                -Because "$($file.Name) should contain at least one function"
            $functionMatches[0].Groups[1].Value | Should -Be $file.BaseName `
                -Because "$($file.Name) function name should match filename"
        }
    }

    It 'Each private function file contains exactly one function matching the filename' {
        $privateFiles = Get-ChildItem -Path (Join-Path $sourceRoot 'Private') -Filter '*.ps1'
        foreach ($file in $privateFiles) {
            $content = Get-Content -Path $file.FullName -Raw
            $functionMatches = [regex]::Matches($content, '(?m)^function\s+(\S+)')
            $functionMatches.Count | Should -BeGreaterOrEqual 1 `
                -Because "$($file.Name) should contain at least one function"
            $functionMatches[0].Groups[1].Value | Should -Be $file.BaseName `
                -Because "$($file.Name) function name should match filename"
        }
    }

    It 'All source files have valid PowerShell syntax' {
        foreach ($file in $allSourceFiles) {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile(
                $file.FullName,
                [ref]$null,
                [ref]$errors
            ) | Out-Null
            $errors | Should -HaveCount 0 `
                -Because "$($file.Name) should have no syntax errors"
        }
    }

    It 'No source file contains #Requires statements' {
        foreach ($file in $allSourceFiles) {
            $content = Get-Content -Path $file.FullName -Raw
            $content | Should -Not -Match '#Requires' `
                -Because "Dependencies should be declared in the module manifest, not in individual source files"
        }
    }
}

Describe 'Project Structure' -Tag 'QA' {
    It 'Has source/Public directory' {
        Join-Path $sourceRoot 'Public' | Should -Exist
    }

    It 'Has source/Private directory' {
        Join-Path $sourceRoot 'Private' | Should -Exist
    }

    It 'Has module manifest' {
        $manifestPath | Should -Exist
    }

    It 'Has module script' {
        Join-Path $sourceRoot 'RC4ADCheck.psm1' | Should -Exist
    }

    It 'Has build.yaml' {
        Join-Path $projectRoot 'build.yaml' | Should -Exist
    }

    It 'Has build.ps1' {
        Join-Path $projectRoot 'build.ps1' | Should -Exist
    }

    It 'Has RequiredModules.psd1' {
        Join-Path $projectRoot 'RequiredModules.psd1' | Should -Exist
    }

    It 'Has GitVersion.yml' {
        Join-Path $projectRoot 'GitVersion.yml' | Should -Exist
    }

    It 'Has tests directory' {
        Join-Path $projectRoot 'tests' | Should -Exist
    }

    It 'Has CHANGELOG.md' {
        Join-Path $projectRoot 'CHANGELOG.md' | Should -Exist
    }

    It 'Has LICENSE' {
        Join-Path $projectRoot 'LICENSE' | Should -Exist
    }
}
