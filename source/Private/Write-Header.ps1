function Write-Header {
    param([string]$Title, [string]$Color = "Cyan")
    
    Write-Host "`n$("=" * 80)" -ForegroundColor $Color
    Write-Host $Title -ForegroundColor $Color
    Write-Host $("=" * 80) -ForegroundColor $Color
}
