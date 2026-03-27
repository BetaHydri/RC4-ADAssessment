function Write-ComparisonSection {
    <#
    .SYNOPSIS
        Writes a sub-section header for assessment comparison output.

    .DESCRIPTION
        Displays a sub-section heading using a line of dashes below the title, formatted in
        yellow. Used to visually separate sub-categories within a comparison block produced
        by Invoke-AssessmentComparison.

    .PARAMETER Title
        The title text to display as the sub-section heading.

    .EXAMPLE
        Write-ComparisonSection -Title "Domain Controller Changes"
    #>
    param([string]$Title)
    Write-Host "`n$Title" -ForegroundColor Yellow
    Write-Host $(("-" * 60)) -ForegroundColor Yellow
}
