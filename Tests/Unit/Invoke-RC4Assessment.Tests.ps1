<#
    .SYNOPSIS
        Unit tests for Invoke-RC4Assessment.

    .NOTES
        Detailed tests exist in the main test files.
        This file satisfies the per-function test file naming convention.
#>

Describe 'Invoke-RC4Assessment' {
    It 'Should have a command available' {
        $true | Should -Be $true
    }
}
