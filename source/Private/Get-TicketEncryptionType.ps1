function Get-TicketEncryptionType {
    <#
    .SYNOPSIS
        Maps a Kerberos ticket encryption type integer from event logs to its name.

    .DESCRIPTION
        Translates the numeric EncryptionType field found in Kerberos event log entries
        (e.g., Event ID 4768, 4769) to a descriptive string such as RC4-HMAC, AES256-HMAC-SHA1,
        or DES-CBC-MD5. Returns an "Unknown" string with the hex value for unrecognised types.

    .PARAMETER EncryptionType
        The integer encryption type value from a Kerberos event log entry.

    .EXAMPLE
        Get-TicketEncryptionType -EncryptionType 0x17
        # Returns "RC4-HMAC"
    #>
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
