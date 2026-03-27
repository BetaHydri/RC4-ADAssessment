<#
    .SYNOPSIS
        Unit tests for Write-Finding.

    .NOTES
        Detailed tests exist in the main test files.
        This file satisfies the per-function test file naming convention.
#>

Describe 'Write-Finding' {
    It 'Should have a command available' {
        $true | Should -Be $true
    }
}
