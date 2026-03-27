function Write-Finding {
    <#
    .SYNOPSIS
        Writes a colour-coded assessment finding line to the console.

    .DESCRIPTION
        Displays a single assessment finding with a status symbol and colour-coded text.
        Supported status values are OK (green check), WARNING (yellow warning), CRITICAL
        (red cross), and INFO (cyan info). An optional detail line is printed in grey when
        provided. This function is the primary output primitive used throughout the module.

    .PARAMETER Status
        The severity level of the finding. Accepted values: OK, WARNING, CRITICAL, INFO.

    .PARAMETER Message
        The main finding message text to display.

    .PARAMETER Detail
        An optional supplementary detail string printed indented below the message.

    .EXAMPLE
        Write-Finding -Status "OK" -Message "AES encryption is enabled on all DCs"

    .EXAMPLE
        Write-Finding -Status "CRITICAL" -Message "DES is enabled" -Detail "3 accounts affected"
    #>
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
