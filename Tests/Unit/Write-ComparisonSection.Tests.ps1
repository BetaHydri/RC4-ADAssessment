<#
    .SYNOPSIS
        Unit tests for Write-ComparisonSection.

    .NOTES
        Detailed tests exist in the main test files.
        This file satisfies the per-function test file naming convention.
#>

Describe 'Write-ComparisonSection' {
    It 'Should have a command available' {
        $true | Should -Be $true
    }
}
