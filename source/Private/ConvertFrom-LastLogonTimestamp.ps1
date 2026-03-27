function ConvertFrom-LastLogonTimestamp {
    <#
    .SYNOPSIS
        Converts a raw Active Directory lastLogonTimestamp value to a DateTime and age in days.

    .DESCRIPTION
        Converts the integer file-time value stored in the Active Directory lastLogonTimestamp
        attribute into a human-readable DateTime object and calculates how many days ago the
        logon occurred. Returns a hashtable with LastLogon and LastLogonDaysAgo keys.
        If the raw value is null or zero, LastLogon will be $null and LastLogonDaysAgo will be -1.

    .PARAMETER RawValue
        The raw integer file-time value from the Active Directory lastLogonTimestamp attribute.

    .EXAMPLE
        $result = ConvertFrom-LastLogonTimestamp -RawValue 133500000000000000
        $result.LastLogon        # Returns the DateTime of the last logon
        $result.LastLogonDaysAgo # Returns number of days since last logon
    #>
    param($RawValue)

    $result = @{ LastLogon = $null; LastLogonDaysAgo = -1 }
    if ($RawValue) {
        try {
            $result.LastLogon = [DateTime]::FromFileTime($RawValue)
            $result.LastLogonDaysAgo = ((Get-Date) - $result.LastLogon).Days
        }
        catch { Write-Verbose "Could not convert FileTime value: $($_.Exception.Message)" }
    }
    return $result
}
