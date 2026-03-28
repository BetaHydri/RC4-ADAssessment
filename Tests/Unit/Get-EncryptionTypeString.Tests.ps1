InModuleScope 'RC4ADCheck' {
    Describe 'Get-EncryptionTypeString' {
    It 'Returns "Not Set (Default)" for zero' {
        Get-EncryptionTypeString -Value 0 | Should -Be 'Not Set (Default)'
    }

    It 'Returns "DES-CBC-CRC" for value 1' {
        Get-EncryptionTypeString -Value 1 | Should -Be 'DES-CBC-CRC'
    }

    It 'Returns "DES-CBC-MD5" for value 2' {
        Get-EncryptionTypeString -Value 2 | Should -Be 'DES-CBC-MD5'
    }

    It 'Returns "RC4-HMAC" for value 4' {
        Get-EncryptionTypeString -Value 4 | Should -Be 'RC4-HMAC'
    }

    It 'Returns "AES128-HMAC" for value 8' {
        Get-EncryptionTypeString -Value 8 | Should -Be 'AES128-HMAC'
    }

    It 'Returns "AES256-HMAC" for value 16' {
        Get-EncryptionTypeString -Value 16 | Should -Be 'AES256-HMAC'
    }

    It 'Returns combined types for value 24 (AES128+AES256)' {
        Get-EncryptionTypeString -Value 24 | Should -Be 'AES128-HMAC, AES256-HMAC'
    }

    It 'Returns all types for value 31' {
        Get-EncryptionTypeString -Value 31 | Should -Be 'DES-CBC-CRC, DES-CBC-MD5, RC4-HMAC, AES128-HMAC, AES256-HMAC'
    }
}
}
