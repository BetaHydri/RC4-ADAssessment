InModuleScope 'RC4-ADAssessment' {
Describe 'Show-ManualValidationGuidance' {
    BeforeEach {
        Mock -ModuleName 'RC4-ADAssessment' Write-Host {}
    }

    It 'Does not throw' {
        { Show-ManualValidationGuidance } | Should -Not -Throw
    }

    It 'Calls Write-Host multiple times' {
        Show-ManualValidationGuidance | Out-Null
        Should -Invoke -ModuleName 'RC4-ADAssessment' -CommandName Write-Host -Times 5 -Exactly:$false
    }
}
}
