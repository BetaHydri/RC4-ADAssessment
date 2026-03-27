function Get-EncryptionTypeString {
    <#
    .SYNOPSIS
        Converts a msDS-SupportedEncryptionTypes bitmask integer to a human-readable string.

    .DESCRIPTION
        Interprets the integer bitmask stored in the msDS-SupportedEncryptionTypes Active
        Directory attribute and returns a comma-separated string listing each enabled encryption
        type (DES-CBC-CRC, DES-CBC-MD5, RC4-HMAC, AES128-HMAC, AES256-HMAC).
        Returns "Not Set (Default)" when the value is 0 or $null.

    .PARAMETER Value
        The integer bitmask value from msDS-SupportedEncryptionTypes.

    .EXAMPLE
        Get-EncryptionTypeString -Value 24
        # Returns "AES128-HMAC, AES256-HMAC"
    #>
    param([int]$Value)
    
    if (-not $Value -or $Value -eq 0) {
        return "Not Set (Default)"
    }
    
    $types = @()
    if ($Value -band 0x1) { $types += "DES-CBC-CRC" }
    if ($Value -band 0x2) { $types += "DES-CBC-MD5" }
    if ($Value -band 0x4) { $types += "RC4-HMAC" }
    if ($Value -band 0x8) { $types += "AES128-HMAC" }
    if ($Value -band 0x10) { $types += "AES256-HMAC" }
    
    return ($types -join ", ")
}
