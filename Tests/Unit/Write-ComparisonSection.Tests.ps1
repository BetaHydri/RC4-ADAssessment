InModuleScope 'RC4-ADAssessment' {
    Describe 'Write-ComparisonSection' {
    BeforeEach {
        Mock Write-Host {}
    }

    It 'Does not throw with a title' {
        { Write-ComparisonSection -Title 'Test Section' } | Should -Not -Throw
    }

    It 'Calls Write-Host exactly 2 times (title + separator)' {
        Write-ComparisonSection -Title 'Test'
        Should -Invoke Write-Host -Times 2 -Exactly
    }
}
}
