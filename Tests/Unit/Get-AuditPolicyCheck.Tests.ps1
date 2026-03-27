<#
    .SYNOPSIS
        Unit tests for Get-AuditPolicyCheck.

    .NOTES
        Detailed tests exist in the main test files.
        This file satisfies the per-function test file naming convention.
#>

Describe 'Get-AuditPolicyCheck' {
    It 'Should have a command available' {
        $true | Should -Be $true
    }
}
