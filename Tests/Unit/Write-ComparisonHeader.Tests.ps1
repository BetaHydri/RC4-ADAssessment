InModuleScope 'RC4-ADAssessment' {
    Describe 'Write-ComparisonHeader' {
    BeforeEach {
        Mock Write-Host {}
    }

    It 'Does not throw with a title' {
        { Write-ComparisonHeader -Title 'Test Header' } | Should -Not -Throw
    }

    It 'Calls Write-Host at least 3 times (top line, title, bottom line)' {
        Write-ComparisonHeader -Title 'Test'
        Should -Invoke Write-Host -Times 3 -Exactly
    }
}
}
