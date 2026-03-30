InModuleScope 'RC4ADCheck' {
Describe 'Show-ManualValidationGuidance' {
    BeforeEach {
        Mock -ModuleName 'RC4ADCheck' Write-Host {}
    }

    It 'Does not throw' {
        { Show-ManualValidationGuidance } | Should -Not -Throw
    }

    It 'Calls Write-Host multiple times' {
        Show-ManualValidationGuidance | Out-Null
        Should -Invoke -ModuleName 'RC4ADCheck' -CommandName Write-Host -Times 5 -Exactly:$false
    }
}
}
