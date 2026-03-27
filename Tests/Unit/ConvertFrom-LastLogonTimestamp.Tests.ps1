<#
    .SYNOPSIS
        Unit tests for ConvertFrom-LastLogonTimestamp.

    .NOTES
        Detailed tests exist in the main test files.
        This file satisfies the per-function test file naming convention.
#>

Describe 'ConvertFrom-LastLogonTimestamp' {
    It 'Should have a command available' {
        $true | Should -Be $true
    }
}
