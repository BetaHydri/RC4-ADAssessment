function Write-Header {
    <#
    .SYNOPSIS
        Writes a major section header block to the console.

    .DESCRIPTION
        Displays a header block consisting of a line of equals signs, the title text, and
        another line of equals signs. All output is rendered in the specified console colour.
        Used to visually separate top-level sections in the assessment report output.

    .PARAMETER Title
        The title text to display inside the header block.

    .PARAMETER Color
        The console foreground colour used for the header. Defaults to Cyan.

    .EXAMPLE
        Write-Header -Title "RC4 Kerberos Encryption Assessment"

    .EXAMPLE
        Write-Header -Title "Domain: contoso.com" -Color "Yellow"
    #>
    param([string]$Title, [string]$Color = "Cyan")

    Write-Host "`n$("=" * 80)" -ForegroundColor $Color
    Write-Host $Title -ForegroundColor $Color
    Write-Host $("=" * 80) -ForegroundColor $Color
}
