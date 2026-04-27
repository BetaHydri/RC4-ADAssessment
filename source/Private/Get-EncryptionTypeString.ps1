function Get-EncryptionTypeString {
    <#
    .SYNOPSIS
        Converts a Kerberos encryption-type bitmask integer to a human-readable string.

    .DESCRIPTION
        Interprets the 32-bit bitmask used by msDS-SupportedEncryptionTypes (AD attribute),
        DefaultDomainSupportedEncTypes (KDC registry), or the GPO-written
        SupportedEncryptionTypes (Policies registry path). The same bit positions carry
        different semantics depending on context:

        - msds  : AD attribute. Feature flags (bits 16-19) are meaningful. Bit 31 is not.
        - ddset : KDC registry fallback. Only etype bits 0-5 are meaningful.
        - gpo   : GPO-written value. "Future encryption types" is bits 5-30 (0x7FFFFFE0),
                   NOT bit 31. Feature flags are not meaningful.

        Returns "Not Set (Default)" when the value is 0 or $null.

    .PARAMETER Value
        The integer bitmask value to decode.

    .PARAMETER Context
        Which of the three bitmask contexts to decode for.
        Defaults to 'msds' (the AD attribute).

    .EXAMPLE
        Get-EncryptionTypeString -Value 24
        # Returns "AES128-HMAC, AES256-HMAC"

    .EXAMPLE
        Get-EncryptionTypeString -Value 0x7FFFFFF8 -Context gpo
        # Returns "AES128-HMAC, AES256-HMAC, Future (bits 5-30)"
    #>
    param(
        [int]$Value,

        [ValidateSet('msds', 'ddset', 'gpo')]
        [string]$Context = 'msds'
    )

    if (-not $Value -or $Value -eq 0) {
        return "Not Set (Default)"
    }

    $types = @()
    if ($Value -band 0x1) { $types += "DES-CBC-CRC" }
    if ($Value -band 0x2) { $types += "DES-CBC-MD5" }
    if ($Value -band 0x4) { $types += "RC4-HMAC" }
    if ($Value -band 0x8) { $types += "AES128-HMAC" }
    if ($Value -band 0x10) { $types += "AES256-HMAC" }
    if ($Value -band 0x20) { $types += "AES256-HMAC-SK" }

    # Feature flags (bits 16-19) only meaningful on the AD attribute.
    if ($Context -eq 'msds') {
        if ($Value -band 0x10000) { $types += "FAST" }
        if ($Value -band 0x20000) { $types += "Compound-Identity" }
        if ($Value -band 0x40000) { $types += "Claims" }
        if ($Value -band 0x80000) { $types += "Resource-SID-Compression" }
    }

    # "Future encryption types" handling differs per context.
    switch ($Context) {
        'msds' {
            if ($Value -band ([int]0x80000000)) {
                $types += "bit 31 set (not meaningful on msDS-SET)"
            }
        }
        'ddset' {
            if ($Value -band ([int]0x80000000)) {
                $types += "bit 31 set (not meaningful on DDSET)"
            }
        }
        'gpo' {
            if (($Value -band 0x7FFFFFE0) -eq 0x7FFFFFE0) {
                $types += "Future (bits 5-30)"
            }
            elseif ($Value -band ([int]0x80000000)) {
                $types += "bit 31 set (not the GPO Future range)"
            }
        }
    }

    return ($types -join ", ")
}
