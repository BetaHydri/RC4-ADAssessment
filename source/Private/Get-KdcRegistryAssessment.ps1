function Get-KdcRegistryAssessment {
    <#
    .SYNOPSIS
        Assesses KDC registry settings on Domain Controllers for RC4 disablement configuration.

    .DESCRIPTION
        Connects to each Domain Controller via WinRM and reads three KDC-related registry values:
        RC4DefaultDisablementPhase (controls RC4 deprecation phase),
        DefaultDomainSupportedEncTypes (controls which encryption types are advertised by default),
        and SupportedEncryptionTypes from the GPO Policies path (the GPO-written etype filter).
        The GPO registry value is compared against each DC's msDS-SupportedEncryptionTypes AD
        attribute to detect drift (GPO applied but Kerberos service not yet restarted, or manual
        override). Returns a hashtable with status for each setting, per-DC details, drift
        findings, and a list of DCs that could not be queried. AzureADKerberos proxy objects are
        automatically excluded.

    .PARAMETER ServerParams
        A hashtable of parameters passed through to Active Directory cmdlets. Supports a
        'Server' key to target a specific Domain Controller.

    .EXAMPLE
        $params = @{ Server = 'dc01.contoso.com' }
        $result = Get-KdcRegistryAssessment -ServerParams $params
        $result.RC4DefaultDisablementPhase.Status
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '')]
    param(
        [hashtable]$ServerParams
    )

    Write-Section "KDC Registry Configuration Assessment"

    $assessment = @{
        DefaultDomainSupportedEncTypes = @{
            Configured  = $false
            Value       = $null
            Types       = ""
            IncludesRC4 = $false
            IncludesAES = $false
            Status      = "Unknown"
        }
        RC4DefaultDisablementPhase     = @{
            Configured = $false
            Value      = $null
            Status     = "Unknown"
        }
        QueriedDCs                     = @()
        FailedDCs                      = @()
        Details                        = @()
        EtypeDrift                     = @()
        TotalEtypeDrift                = 0
    }

    try {
        # Get domain info
        if ($ServerParams.ContainsKey('Server')) {
            try {
                $null = Get-ADDomain -Server $ServerParams['Server'] -ErrorAction Stop
            }
            catch {
                throw "Failed to contact Domain Controller '$($ServerParams['Server'])': $($_.Exception.Message)"
            }
        }
        else {
            $null = Get-ADDomain
        }

        # Get all DCs using authoritative DC Locator
        $dcs = @(Get-ADDomainController -Filter * @ServerParams)

        if (-not $dcs -or $dcs.Count -eq 0) {
            Write-Finding -Status "WARNING" -Message "No Domain Controllers found for registry assessment"
            return $assessment
        }

        Write-Finding -Status "INFO" -Message "Checking KDC registry keys on $($dcs.Count) Domain Controller(s)"

        $ddsetPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
        $phasePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'

        foreach ($dc in $dcs) {
            $dcName = $dc.HostName
            Write-Host "  $([char]0x2022) Querying $dcName..." -ForegroundColor Cyan

            try {
                $regValues = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    param($DdsetPath, $PhasePath)
                    $result = @{ DefaultDomainSupportedEncTypes = $null; RC4DefaultDisablementPhase = $null; GPOSupportedEncryptionTypes = $null }
                    try {
                        $val = Get-ItemProperty -Path $DdsetPath -Name 'DefaultDomainSupportedEncTypes' -ErrorAction SilentlyContinue
                        if ($val) { $result.DefaultDomainSupportedEncTypes = $val.DefaultDomainSupportedEncTypes }
                    }
                    catch { Write-Verbose "Registry read failed: $($_.Exception.Message)" }
                    try {
                        $val = Get-ItemProperty -Path $PhasePath -Name 'RC4DefaultDisablementPhase' -ErrorAction SilentlyContinue
                        if ($val) { $result.RC4DefaultDisablementPhase = $val.RC4DefaultDisablementPhase }
                    }
                    catch { Write-Verbose "Registry read failed: $($_.Exception.Message)" }
                    try {
                        $val = Get-ItemProperty -Path $PhasePath -Name 'SupportedEncryptionTypes' -ErrorAction SilentlyContinue
                        if ($val) { $result.GPOSupportedEncryptionTypes = $val.SupportedEncryptionTypes }
                    }
                    catch { Write-Verbose "Registry read failed: $($_.Exception.Message)" }
                    $result
                } -ArgumentList $ddsetPath, $phasePath -ErrorAction Stop

                $assessment.QueriedDCs += $dcName

                $dcDetail = @{
                    Name                           = $dcName
                    DefaultDomainSupportedEncTypes = $regValues.DefaultDomainSupportedEncTypes
                    RC4DefaultDisablementPhase     = $regValues.RC4DefaultDisablementPhase
                    GPOSupportedEncryptionTypes    = $regValues.GPOSupportedEncryptionTypes
                }
                $assessment.Details += $dcDetail

                # Process DefaultDomainSupportedEncTypes
                if ($null -ne $regValues.DefaultDomainSupportedEncTypes) {
                    $encVal = [int]$regValues.DefaultDomainSupportedEncTypes
                    $assessment.DefaultDomainSupportedEncTypes.Configured = $true
                    $assessment.DefaultDomainSupportedEncTypes.Value = $encVal
                    $assessment.DefaultDomainSupportedEncTypes.Types = Get-EncryptionTypeString -Value $encVal -Context ddset
                    $assessment.DefaultDomainSupportedEncTypes.IncludesRC4 = [bool]($encVal -band 0x4)
                    $assessment.DefaultDomainSupportedEncTypes.IncludesAES = [bool]($encVal -band 0x18)

                    Write-Host "    DefaultDomainSupportedEncTypes: $encVal ($(Get-EncryptionTypeString -Value $encVal -Context ddset))" -ForegroundColor Gray
                }

                # Process RC4DefaultDisablementPhase
                if ($null -ne $regValues.RC4DefaultDisablementPhase) {
                    $assessment.RC4DefaultDisablementPhase.Configured = $true
                    $assessment.RC4DefaultDisablementPhase.Value = [int]$regValues.RC4DefaultDisablementPhase

                    Write-Host "    RC4DefaultDisablementPhase: $($regValues.RC4DefaultDisablementPhase)" -ForegroundColor Gray
                }

                # Process GPO SupportedEncryptionTypes and detect drift against msDS-SupportedEncryptionTypes
                if ($null -ne $regValues.GPOSupportedEncryptionTypes) {
                    $gpoEncVal = [int]$regValues.GPOSupportedEncryptionTypes
                    # Strip the high bit (0x80000000) that GPO adds as a "configured" flag
                    $gpoEffective = $gpoEncVal -band 0x7FFFFFFF
                    Write-Host "    GPO SupportedEncryptionTypes: 0x$($gpoEncVal.ToString('X')) (effective: 0x$($gpoEffective.ToString('X')) = $(Get-EncryptionTypeString -Value $gpoEffective))" -ForegroundColor Gray

                    # Read the DC's msDS-SupportedEncryptionTypes from AD for drift comparison
                    try {
                        $dcComputer = Get-ADComputer $dc.ComputerObjectDN -Properties 'msDS-SupportedEncryptionTypes' @ServerParams -ErrorAction Stop
                        $msdsSET = $dcComputer.'msDS-SupportedEncryptionTypes'

                        if ($null -ne $msdsSET -and $gpoEffective -ne [int]$msdsSET) {
                            $driftEntry = @{
                                DCName       = $dcName
                                GPORegistry  = $gpoEncVal
                                GPOEffective = $gpoEffective
                                MsDsSET      = [int]$msdsSET
                                GPOTypes     = Get-EncryptionTypeString -Value $gpoEffective
                                ADTypes      = Get-EncryptionTypeString -Value ([int]$msdsSET)
                            }
                            $assessment.EtypeDrift += $driftEntry
                            $assessment.TotalEtypeDrift++
                            Write-Finding -Status "WARNING" -Message "Etype drift on $dcName -- GPO registry (0x$($gpoEffective.ToString('X'))) differs from AD msDS-SupportedEncryptionTypes (0x$($msdsSET.ToString('X')))" `
                                -Detail "GPO: $(Get-EncryptionTypeString -Value $gpoEffective) | AD: $(Get-EncryptionTypeString -Value ([int]$msdsSET)). Restart the Kerberos service (Restart-Service Kdc) on $dcName or wait for the next refresh cycle."
                        }
                        elseif ($null -ne $msdsSET) {
                            Write-Host "    msDS-SupportedEncryptionTypes: 0x$($msdsSET.ToString('X')) -- matches GPO (no drift)" -ForegroundColor Gray
                        }
                    }
                    catch {
                        Write-Verbose "Could not read msDS-SupportedEncryptionTypes for $dcName : $($_.Exception.Message)"
                    }
                }
            }
            catch {
                # WinRM failed — try local registry read if we're on this DC
                $isLocalDC = $false
                try {
                    $localHostName = [System.Net.Dns]::GetHostEntry('localhost').HostName
                    $isLocalDC = ($dcName -eq $localHostName)
                }
                catch {
                    Write-Verbose "DNS lookup for localhost failed: $($_.Exception.Message)"
                }
                if (-not $isLocalDC) {
                    $isLocalDC = ($dc.Name -eq $env:COMPUTERNAME)
                }
                if ($isLocalDC) {
                    Write-Host "    $([char]0x26A0) WinRM unavailable, reading local registry..." -ForegroundColor DarkYellow
                    try {
                        $regValues = @{ DefaultDomainSupportedEncTypes = $null; RC4DefaultDisablementPhase = $null; GPOSupportedEncryptionTypes = $null }
                        try {
                            $val = Get-ItemProperty -Path $ddsetPath -Name 'DefaultDomainSupportedEncTypes' -ErrorAction SilentlyContinue
                            if ($val) { $regValues.DefaultDomainSupportedEncTypes = $val.DefaultDomainSupportedEncTypes }
                        } catch { Write-Verbose "Local registry read failed for DefaultDomainSupportedEncTypes: $($_.Exception.Message)" }
                        try {
                            $val = Get-ItemProperty -Path $phasePath -Name 'RC4DefaultDisablementPhase' -ErrorAction SilentlyContinue
                            if ($val) { $regValues.RC4DefaultDisablementPhase = $val.RC4DefaultDisablementPhase }
                        } catch { Write-Verbose "Local registry read failed for RC4DefaultDisablementPhase: $($_.Exception.Message)" }
                        try {
                            $val = Get-ItemProperty -Path $phasePath -Name 'SupportedEncryptionTypes' -ErrorAction SilentlyContinue
                            if ($val) { $regValues.GPOSupportedEncryptionTypes = $val.SupportedEncryptionTypes }
                        } catch { Write-Verbose "Local registry read failed for SupportedEncryptionTypes: $($_.Exception.Message)" }

                        $assessment.QueriedDCs += $dcName

                        $dcDetail = @{
                            Name                           = $dcName
                            DefaultDomainSupportedEncTypes = $regValues.DefaultDomainSupportedEncTypes
                            RC4DefaultDisablementPhase     = $regValues.RC4DefaultDisablementPhase
                            GPOSupportedEncryptionTypes    = $regValues.GPOSupportedEncryptionTypes
                        }
                        $assessment.Details += $dcDetail

                        if ($null -ne $regValues.DefaultDomainSupportedEncTypes) {
                            $encVal = [int]$regValues.DefaultDomainSupportedEncTypes
                            $assessment.DefaultDomainSupportedEncTypes.Configured = $true
                            $assessment.DefaultDomainSupportedEncTypes.Value = $encVal
                            $assessment.DefaultDomainSupportedEncTypes.Types = Get-EncryptionTypeString -Value $encVal -Context ddset
                            $assessment.DefaultDomainSupportedEncTypes.IncludesRC4 = [bool]($encVal -band 0x4)
                            $assessment.DefaultDomainSupportedEncTypes.IncludesAES = [bool]($encVal -band 0x18)
                            Write-Host "    DefaultDomainSupportedEncTypes: $encVal ($(Get-EncryptionTypeString -Value $encVal -Context ddset))" -ForegroundColor Gray
                        }

                        if ($null -ne $regValues.RC4DefaultDisablementPhase) {
                            $assessment.RC4DefaultDisablementPhase.Configured = $true
                            $assessment.RC4DefaultDisablementPhase.Value = [int]$regValues.RC4DefaultDisablementPhase
                            Write-Host "    RC4DefaultDisablementPhase: $($regValues.RC4DefaultDisablementPhase)" -ForegroundColor Gray
                        }

                        if ($null -ne $regValues.GPOSupportedEncryptionTypes) {
                            $gpoEncVal = [int]$regValues.GPOSupportedEncryptionTypes
                            $gpoEffective = $gpoEncVal -band 0x7FFFFFFF
                            Write-Host "    GPO SupportedEncryptionTypes: 0x$($gpoEncVal.ToString('X')) (effective: 0x$($gpoEffective.ToString('X')) = $(Get-EncryptionTypeString -Value $gpoEffective))" -ForegroundColor Gray
                            try {
                                $dcComputer = Get-ADComputer $dc.ComputerObjectDN -Properties 'msDS-SupportedEncryptionTypes' @ServerParams -ErrorAction Stop
                                $msdsSET = $dcComputer.'msDS-SupportedEncryptionTypes'
                                if ($null -ne $msdsSET -and $gpoEffective -ne [int]$msdsSET) {
                                    $driftEntry = @{
                                        DCName       = $dcName
                                        GPORegistry  = $gpoEncVal
                                        GPOEffective = $gpoEffective
                                        MsDsSET      = [int]$msdsSET
                                        GPOTypes     = Get-EncryptionTypeString -Value $gpoEffective
                                        ADTypes      = Get-EncryptionTypeString -Value ([int]$msdsSET)
                                    }
                                    $assessment.EtypeDrift += $driftEntry
                                    $assessment.TotalEtypeDrift++
                                    Write-Finding -Status "WARNING" -Message "Etype drift on $dcName -- GPO registry (0x$($gpoEffective.ToString('X'))) differs from AD msDS-SupportedEncryptionTypes (0x$($msdsSET.ToString('X')))" `
                                        -Detail "GPO: $(Get-EncryptionTypeString -Value $gpoEffective) | AD: $(Get-EncryptionTypeString -Value ([int]$msdsSET)). Restart the Kerberos service (Restart-Service Kdc) on $dcName or wait for the next refresh cycle."
                                }
                                elseif ($null -ne $msdsSET) {
                                    Write-Host "    msDS-SupportedEncryptionTypes: 0x$($msdsSET.ToString('X')) -- matches GPO (no drift)" -ForegroundColor Gray
                                }
                            }
                            catch {
                                Write-Verbose "Could not read msDS-SupportedEncryptionTypes for $dcName : $($_.Exception.Message)"
                            }
                        }
                    }
                    catch {
                        $assessment.FailedDCs += @{ Name = $dcName; Error = "Local fallback failed: $($_.Exception.Message)" }
                        Write-Host "    $([char]0x26A0) Local registry read also failed on $dcName : $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
                else {
                    $assessment.FailedDCs += @{ Name = $dcName; Error = $_.Exception.Message }
                    Write-Host "    $([char]0x26A0) Could not query registry on $dcName : $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }

        # Etype drift summary
        if ($assessment.TotalEtypeDrift -gt 0) {
            Write-Finding -Status "WARNING" -Message "GPO-vs-AD etype drift detected on $($assessment.TotalEtypeDrift) DC(s) -- Kerberos service restart may be pending"
        }
        elseif ($assessment.QueriedDCs.Count -gt 0 -and ($assessment.Details | Where-Object { $null -ne $_.GPOSupportedEncryptionTypes }).Count -gt 0) {
            Write-Finding -Status "OK" -Message "No GPO-vs-AD etype drift detected -- all DCs consistent"
        }

        # Assess DefaultDomainSupportedEncTypes
        if ($assessment.DefaultDomainSupportedEncTypes.Configured) {
            if (-not $assessment.DefaultDomainSupportedEncTypes.IncludesAES) {
                $assessment.DefaultDomainSupportedEncTypes.Status = "CRITICAL"
                Write-Finding -Status "CRITICAL" -Message "DefaultDomainSupportedEncTypes does NOT include AES" `
                    -Detail "Value: $($assessment.DefaultDomainSupportedEncTypes.Value) ($($assessment.DefaultDomainSupportedEncTypes.Types))"
            }
            elseif ($assessment.DefaultDomainSupportedEncTypes.IncludesRC4) {
                $assessment.DefaultDomainSupportedEncTypes.Status = "WARNING"
                Write-Finding -Status "WARNING" -Message "DefaultDomainSupportedEncTypes includes RC4 -- overrides enforcement for ALL accounts without explicit msDS-SupportedEncryptionTypes" `
                    -Detail "Value: $($assessment.DefaultDomainSupportedEncTypes.Value) ($($assessment.DefaultDomainSupportedEncTypes.Types)). Per-account RC4 exceptions (0x1C) do NOT require DDSET to include RC4. Consider removing RC4 from DDSET or deleting the key to use the OS default (0x18, AES-only)."
            }
            else {
                $assessment.DefaultDomainSupportedEncTypes.Status = "OK"
                Write-Finding -Status "OK" -Message "DefaultDomainSupportedEncTypes is AES-only" `
                    -Detail "Value: $($assessment.DefaultDomainSupportedEncTypes.Value) ($($assessment.DefaultDomainSupportedEncTypes.Types))"
            }
        }
        else {
            $assessment.DefaultDomainSupportedEncTypes.Status = "NOT SET"
            Write-Finding -Status "INFO" -Message "DefaultDomainSupportedEncTypes registry key is not set (uses OS defaults)"
        }

        # Assess RC4DefaultDisablementPhase
        if ($assessment.RC4DefaultDisablementPhase.Configured) {
            $phase = $assessment.RC4DefaultDisablementPhase.Value
            switch ($phase) {
                0 {
                    $assessment.RC4DefaultDisablementPhase.Status = "WARNING"
                    Write-Finding -Status "WARNING" -Message "RC4DefaultDisablementPhase = 0 (RC4 disablement NOT active -- rollback state)" `
                        -Detail "RC4 allowed for all accounts. Set to 1 (audit) to log KDCSVC events 201-209, then 2 for Enforcement. Restart-Service Kdc required after change."
                }
                1 {
                    $assessment.RC4DefaultDisablementPhase.Status = "OK"
                    Write-Finding -Status "OK" -Message "RC4DefaultDisablementPhase = 1 (Audit checkpoint active)" `
                        -Detail "RC4 still allowed. KDCSVC events 201/202 and 206/207 logged per RC4 request. Same ticket-issuance behaviour as 0, but with per-request audit events. When no events remain, set to 2 for Enforcement. Restart-Service Kdc required after change."
                }
                2 {
                    $assessment.RC4DefaultDisablementPhase.Status = "OK"
                    Write-Finding -Status "OK" -Message "RC4DefaultDisablementPhase = 2 (Enforcement mode active)" `
                        -Detail "RC4 is blocked for accounts without explicit RC4 in msDS-SupportedEncryptionTypes (CVE-2026-20833)"
                }
                default {
                    $assessment.RC4DefaultDisablementPhase.Status = "INFO"
                    Write-Finding -Status "INFO" -Message "RC4DefaultDisablementPhase = $phase" `
                        -Detail "Unexpected value - check Microsoft documentation for current phase definitions"
                }
            }
        }
        else {
            $assessment.RC4DefaultDisablementPhase.Status = "NOT SET"
            Write-Finding -Status "INFO" -Message "RC4DefaultDisablementPhase registry key is not set (implicit enforcement after April 2026 CU)" `
                -Detail "After KB5078763 (April 2026), 'not set' equals enforcement -- RC4 blocked for accounts without explicit msDS-SupportedEncryptionTypes. Set to 1 to roll back to audit mode. Restart-Service Kdc required after change."
        }

        if ($assessment.FailedDCs.Count -gt 0) {
            Write-Host "`n  $([char]0x26A0) Could not query registry on $($assessment.FailedDCs.Count) DC(s) - WinRM may not be enabled" -ForegroundColor Yellow
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -match "Failed to contact Domain Controller '([^']+)'") {
            Write-Finding -Status "CRITICAL" -Message $errorMsg
        }
        else {
            Write-Finding -Status "WARNING" -Message "Error checking KDC registry: $errorMsg"
        }
    }

    return $assessment
}
