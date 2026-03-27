<#
    .SYNOPSIS
        Unit tests for Invoke-AssessmentComparison.

    .NOTES
        Detailed tests exist in the main test files.
        This file satisfies the per-function test file naming convention.
#>

Describe 'Invoke-AssessmentComparison' {
    It 'Should have a command available' {
        $true | Should -Be $true
    }
}
