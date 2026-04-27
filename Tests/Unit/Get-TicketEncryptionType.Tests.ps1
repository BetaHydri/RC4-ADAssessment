InModuleScope 'RC4-ADAssessment' {
    Describe 'Get-TicketEncryptionType' {
    It 'Returns "DES-CBC-CRC" for 0x1' {
        Get-TicketEncryptionType -EncryptionType 0x1 | Should -Be 'DES-CBC-CRC'
    }

    It 'Returns "DES-CBC-MD5" for 0x3' {
        Get-TicketEncryptionType -EncryptionType 0x3 | Should -Be 'DES-CBC-MD5'
    }

    It 'Returns "AES128-HMAC-SHA1" for 0x11' {
        Get-TicketEncryptionType -EncryptionType 0x11 | Should -Be 'AES128-HMAC-SHA1'
    }

    It 'Returns "AES256-HMAC-SHA1" for 0x12' {
        Get-TicketEncryptionType -EncryptionType 0x12 | Should -Be 'AES256-HMAC-SHA1'
    }

    It 'Returns "RC4-HMAC" for 0x17' {
        Get-TicketEncryptionType -EncryptionType 0x17 | Should -Be 'RC4-HMAC'
    }

    It 'Returns "RC4-HMAC-EXP" for 0x18' {
        Get-TicketEncryptionType -EncryptionType 0x18 | Should -Be 'RC4-HMAC-EXP'
    }

    It 'Returns Unknown with hex value for unrecognized type' {
        Get-TicketEncryptionType -EncryptionType 0xFF | Should -Be 'Unknown (0xFF)'
    }

    It 'Returns "Enforcement Block (0xFFFFFFFF)" for -1 (0xFFFFFFFF)' {
        Get-TicketEncryptionType -EncryptionType (-1) | Should -Be 'Enforcement Block (0xFFFFFFFF)'
    }
}
}
