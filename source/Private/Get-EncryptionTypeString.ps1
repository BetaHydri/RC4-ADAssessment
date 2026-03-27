function Get-EncryptionTypeString {
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
