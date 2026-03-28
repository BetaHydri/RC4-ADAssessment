InModuleScope 'RC4ADCheck' {
    Describe 'ConvertFrom-LastLogonTimestamp' {
        Context 'When RawValue is null' {
        It 'Returns LastLogon as null' {
            $result = ConvertFrom-LastLogonTimestamp -RawValue $null
            $result.LastLogon | Should -BeNullOrEmpty
        }

        It 'Returns LastLogonDaysAgo as -1' {
            $result = ConvertFrom-LastLogonTimestamp -RawValue $null
            $result.LastLogonDaysAgo | Should -Be -1
        }
    }

    Context 'When RawValue is zero' {
        It 'Returns LastLogon as null' {
            $result = ConvertFrom-LastLogonTimestamp -RawValue 0
            $result.LastLogon | Should -BeNullOrEmpty
        }

        It 'Returns LastLogonDaysAgo as -1' {
            $result = ConvertFrom-LastLogonTimestamp -RawValue 0
            $result.LastLogonDaysAgo | Should -Be -1
        }
    }

    Context 'When RawValue is a valid FileTime' {
        It 'Returns a DateTime for LastLogon' {
            $fileTime = (Get-Date).AddDays(-10).ToFileTime()
            $result = ConvertFrom-LastLogonTimestamp -RawValue $fileTime
            $result.LastLogon | Should -BeOfType [DateTime]
        }

        It 'Returns correct LastLogonDaysAgo' {
            $fileTime = (Get-Date).AddDays(-30).ToFileTime()
            $result = ConvertFrom-LastLogonTimestamp -RawValue $fileTime
            $result.LastLogonDaysAgo | Should -BeGreaterOrEqual 29
            $result.LastLogonDaysAgo | Should -BeLessOrEqual 31
        }
    }
}
}
