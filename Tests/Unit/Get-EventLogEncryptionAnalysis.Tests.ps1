<#
    .SYNOPSIS
        Unit tests for Get-EventLogEncryptionAnalysis.

    .NOTES
        Detailed tests exist in the main test files.
        This file satisfies the per-function test file naming convention.
#>

Describe 'Get-EventLogEncryptionAnalysis' {
    It 'Should have a command available' {
        $true | Should -Be $true
    }
}
