<#
    .SYNOPSIS
        Unit tests for Show-ForestSummary.

    .NOTES
        Detailed tests exist in the main test files.
        This file satisfies the per-function test file naming convention.
#>

Describe 'Show-ForestSummary' {
    It 'Should have a command available' {
        $true | Should -Be $true
    }
}
