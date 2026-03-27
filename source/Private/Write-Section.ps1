function Write-Section {
    <#
    .SYNOPSIS
        Writes a sub-section heading with a separator line to the console.

    .DESCRIPTION
        Displays a sub-section heading followed by a line of dashes as a visual separator.
        Output is rendered in the specified console colour. Used throughout the module to
        introduce individual assessment categories within the overall report.

    .PARAMETER Title
        The sub-section title text to display.

    .PARAMETER Color
        The console foreground colour used for the heading and separator. Defaults to Yellow.

    .EXAMPLE
        Write-Section -Title "KDC Registry Configuration Assessment"

    .EXAMPLE
        Write-Section -Title "Event Log Analysis" -Color "Cyan"
    #>
    param([string]$Title, [string]$Color = "Yellow")

    Write-Host "`n$Title" -ForegroundColor $Color
    Write-Host $("-" * 60) -ForegroundColor $Color
}
