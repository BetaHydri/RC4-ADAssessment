function Write-Finding {
    param(
        [string]$Status,  # OK, WARNING, CRITICAL, INFO
        [string]$Message,
        [string]$Detail = ""
    )
    
    $statusSymbol = switch ($Status) {
        "OK" { "$([char]0x2713)"; $color = "Green" }   # ✓ Check mark
        "WARNING" { "$([char]0x26A0) "; $color = "Yellow" } # ⚠ Warning sign
        "CRITICAL" { "$([char]0x2717)"; $color = "Red" }     # ✗ Cross mark
        "INFO" { "$([char]0x24D8) "; $color = "Cyan" }   # ⓘ Circled i (PS 5.1 compatible)
        default { "$([char]0x2022)"; $color = "White" }   # $([char]0x2022) Asterisk (ASCII)
    }
    
    Write-Host "$statusSymbol $Message" -ForegroundColor $color
    if ($Detail) {
        Write-Host "   $Detail" -ForegroundColor Gray
    }
}
