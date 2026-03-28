Describe 'Get-ChangeIndicator' {
    It 'Returns Improved when new value is lower' {
        $result = Get-ChangeIndicator -Old 5 -New 3
        $result.Status | Should -Be 'Improved'
    }

    It 'Returns green color for improvement' {
        $result = Get-ChangeIndicator -Old 10 -New 0
        $result.Color | Should -Be 'Green'
    }

    It 'Returns Worsened when new value is higher' {
        $result = Get-ChangeIndicator -Old 3 -New 5
        $result.Status | Should -Be 'Worsened'
    }

    It 'Returns red color for worsening' {
        $result = Get-ChangeIndicator -Old 0 -New 5
        $result.Color | Should -Be 'Red'
    }

    It 'Returns Unchanged when values are equal' {
        $result = Get-ChangeIndicator -Old 5 -New 5
        $result.Status | Should -Be 'Unchanged'
    }

    It 'Returns gray color for unchanged' {
        $result = Get-ChangeIndicator -Old 0 -New 0
        $result.Color | Should -Be 'Gray'
    }

    It 'Returns a Symbol key in all cases' {
        $result = Get-ChangeIndicator -Old 1 -New 0
        $result.Symbol | Should -Not -BeNullOrEmpty
    }
}
