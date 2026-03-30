InModuleScope 'RC4-ADAssessment' {
    Describe 'Write-Section' {
    BeforeEach {
        Mock Write-Host {}
    }

    It 'Does not throw with a title' {
        { Write-Section -Title 'Test Section' } | Should -Not -Throw
    }

    It 'Calls Write-Host 2 times (title + separator)' {
        Write-Section -Title 'Test'
        Should -Invoke Write-Host -Times 2 -Exactly
    }

    It 'Accepts a custom Color parameter' {
        { Write-Section -Title 'Test' -Color 'Cyan' } | Should -Not -Throw
    }
}
}
