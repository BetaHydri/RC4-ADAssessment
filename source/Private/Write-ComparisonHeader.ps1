function Write-ComparisonHeader {
    param([string]$Title)
    Write-Host "`n$(("=" * 80))" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host $(("=" * 80)) -ForegroundColor Cyan
}
