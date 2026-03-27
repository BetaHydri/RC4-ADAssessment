function Get-ChangeIndicator {
    <#
    .SYNOPSIS
        Returns a directional change indicator comparing two integer values.

    .DESCRIPTION
        Compares an old and a new integer value and returns a hashtable containing a Unicode
        arrow symbol, a console colour, and a status string (Improved, Worsened, or Unchanged).
        Used in assessment comparison output to highlight changes between two assessment runs.

    .PARAMETER Old
        The previous (baseline) integer value.

    .PARAMETER New
        The current integer value to compare against the baseline.

    .EXAMPLE
        $indicator = Get-ChangeIndicator -Old 5 -New 2
        Write-Host $indicator.Symbol -ForegroundColor $indicator.Color
        # Displays a green down-arrow indicating improvement (fewer issues)
    #>
    param([int]$Old, [int]$New)
    
    if ($New -lt $Old) {
        return @{Symbol = "$([char]0x2193)"; Color = "Green"; Status = "Improved" }  # ↓
    }
    elseif ($New -gt $Old) {
        return @{Symbol = "$([char]0x2191)"; Color = "Red"; Status = "Worsened" }  # ↑
    }
    else {
        return @{Symbol = "$([char]0x2192)"; Color = "Gray"; Status = "Unchanged" }  # →
    }
}
