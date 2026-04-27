InModuleScope 'RC4-ADAssessment' {
    Describe 'Get-EncryptionTypeString' {
        Context 'Default context (msds)' {
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

            It 'Returns "AES256-HMAC-SK" for bit 5 (0x20)' {
                Get-EncryptionTypeString -Value 0x20 | Should -Be 'AES256-HMAC-SK'
            }

            It 'Returns combined types for value 24 (AES128+AES256)' {
                Get-EncryptionTypeString -Value 24 | Should -Be 'AES128-HMAC, AES256-HMAC'
            }

            It 'Returns AES128+AES256+AES-SK for value 0x38' {
                Get-EncryptionTypeString -Value 0x38 | Should -Be 'AES128-HMAC, AES256-HMAC, AES256-HMAC-SK'
            }

            It 'Returns all etype bits for value 0x3F' {
                Get-EncryptionTypeString -Value 0x3F | Should -Be 'DES-CBC-CRC, DES-CBC-MD5, RC4-HMAC, AES128-HMAC, AES256-HMAC, AES256-HMAC-SK'
            }

            It 'Flags bit 31 as not meaningful on msDS-SET' {
                Get-EncryptionTypeString -Value ([int]0x80000000) | Should -Be 'bit 31 set (not meaningful on msDS-SET)'
            }

            It 'Returns AES + bit 31 warning for 0x80000018' {
                Get-EncryptionTypeString -Value ([int]0x80000018) | Should -Be 'AES128-HMAC, AES256-HMAC, bit 31 set (not meaningful on msDS-SET)'
            }

            It 'Decodes feature flags on msds context' {
                # FAST (0x10000) + Claims (0x40000) + AES256 (0x10)
                Get-EncryptionTypeString -Value 0x50010 | Should -Be 'AES256-HMAC, FAST, Claims'
            }

            It 'Decodes all four feature flags' {
                Get-EncryptionTypeString -Value 0xF0018 | Should -Be 'AES128-HMAC, AES256-HMAC, FAST, Compound-Identity, Claims, Resource-SID-Compression'
            }
        }

        Context 'DDSET context' {
            It 'Returns AES types without feature flags for ddset' {
                Get-EncryptionTypeString -Value 0xF0018 -Context ddset | Should -Be 'AES128-HMAC, AES256-HMAC'
            }

            It 'Decodes AES-SK (bit 5) on ddset' {
                Get-EncryptionTypeString -Value 0x38 -Context ddset | Should -Be 'AES128-HMAC, AES256-HMAC, AES256-HMAC-SK'
            }

            It 'Flags bit 31 as not meaningful on DDSET' {
                Get-EncryptionTypeString -Value ([int]0x80000018) -Context ddset | Should -Be 'AES128-HMAC, AES256-HMAC, bit 31 set (not meaningful on DDSET)'
            }
        }

        Context 'GPO context' {
            It 'Decodes AES128+AES256+Future for 0x7FFFFFF8' {
                Get-EncryptionTypeString -Value 0x7FFFFFF8 -Context gpo | Should -Be 'AES128-HMAC, AES256-HMAC, AES256-HMAC-SK, Future (bits 5-30)'
            }

            It 'Does not emit feature flags in gpo context' {
                Get-EncryptionTypeString -Value 0xF0018 -Context gpo | Should -Be 'AES128-HMAC, AES256-HMAC'
            }

            It 'Flags bit 31 as not the GPO Future range' {
                Get-EncryptionTypeString -Value ([int]0x80000018) -Context gpo | Should -Be 'AES128-HMAC, AES256-HMAC, bit 31 set (not the GPO Future range)'
            }

            It 'Returns plain AES for 0x18 in gpo context' {
                Get-EncryptionTypeString -Value 0x18 -Context gpo | Should -Be 'AES128-HMAC, AES256-HMAC'
            }
        }
    }
}
