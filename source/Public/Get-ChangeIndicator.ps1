function Get-ChangeIndicator {
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
