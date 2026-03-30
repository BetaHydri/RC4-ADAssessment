InModuleScope 'RC4-ADAssessment' {
    Describe 'Write-Finding' {
    BeforeEach {
        Mock Write-Host {}
    }

    It 'Writes OK status without throwing' {
        { Write-Finding -Status 'OK' -Message 'All good' } | Should -Not -Throw
    }

    It 'Writes WARNING status' {
        { Write-Finding -Status 'WARNING' -Message 'Some issue' } | Should -Not -Throw
    }

    It 'Writes CRITICAL status' {
        { Write-Finding -Status 'CRITICAL' -Message 'Bad' } | Should -Not -Throw
    }

    It 'Writes INFO status' {
        { Write-Finding -Status 'INFO' -Message 'Info' } | Should -Not -Throw
    }

    It 'Writes detail line when Detail is provided' {
        Write-Finding -Status 'OK' -Message 'msg' -Detail 'extra'
        Should -Invoke Write-Host -Times 2 -Exactly
    }

    It 'Writes only message when Detail is empty' {
        Write-Finding -Status 'OK' -Message 'msg'
        Should -Invoke Write-Host -Times 1 -Exactly
    }
}
}
