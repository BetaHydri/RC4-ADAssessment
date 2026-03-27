function Write-ComparisonSection {
    param([string]$Title)
    Write-Host "`n$Title" -ForegroundColor Yellow
    Write-Host $(("-" * 60)) -ForegroundColor Yellow
}
