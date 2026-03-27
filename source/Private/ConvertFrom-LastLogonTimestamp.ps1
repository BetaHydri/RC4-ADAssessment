function ConvertFrom-LastLogonTimestamp {
    param($RawValue)
    
    $result = @{ LastLogon = $null; LastLogonDaysAgo = -1 }
    if ($RawValue) {
        try {
            $result.LastLogon = [DateTime]::FromFileTime($RawValue)
            $result.LastLogonDaysAgo = ((Get-Date) - $result.LastLogon).Days
        }
        catch { }
    }
    return $result
}
