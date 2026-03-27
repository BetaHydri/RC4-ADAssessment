function Get-TicketEncryptionType {
    param([int]$EncryptionType)
    
    # Event log encryption type values
    switch ($EncryptionType) {
        0x1 { return "DES-CBC-CRC" }
        0x3 { return "DES-CBC-MD5" }
        0x11 { return "AES128-HMAC-SHA1" }
        0x12 { return "AES256-HMAC-SHA1" }
        0x17 { return "RC4-HMAC" }
        0x18 { return "RC4-HMAC-EXP" }
        default { return "Unknown (0x$($EncryptionType.ToString('X')))" }
    }
}
