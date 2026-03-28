InModuleScope 'RC4ADCheck' {
    Describe 'Write-Header' {
    BeforeEach {
        Mock Write-Host {}
    }

    It 'Does not throw with a title' {
        { Write-Header -Title 'Test Header' } | Should -Not -Throw
    }

    It 'Calls Write-Host 3 times (top line, title, bottom line)' {
        Write-Header -Title 'Test'
        Should -Invoke Write-Host -Times 3 -Exactly
    }

    It 'Accepts a custom Color parameter' {
        { Write-Header -Title 'Yellow' -Color 'Yellow' } | Should -Not -Throw
    }
}
}
