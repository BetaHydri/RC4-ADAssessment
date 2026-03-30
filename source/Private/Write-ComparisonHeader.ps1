function Write-ComparisonHeader {
    <#
    .SYNOPSIS
        Writes a top-level section header for assessment comparison output.

    .DESCRIPTION
        Displays a prominent header block using a line of equals signs above and below the
        title text, formatted in cyan. Used to visually separate major comparison sections
        in the Invoke-RC4AssessmentComparison output.

    .PARAMETER Title
        The title text to display in the header block.

    .EXAMPLE
        Write-ComparisonHeader -Title "Domain Comparison: contoso.com"
    #>
    param([string]$Title)
    Write-Host "`n$(("=" * 80))" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host $(("=" * 80)) -ForegroundColor Cyan
}
