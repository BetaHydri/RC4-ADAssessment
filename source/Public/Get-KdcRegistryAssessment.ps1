function Get-KdcRegistryAssessment {
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
    }
    
    try {
        # Get domain info
        if ($ServerParams.ContainsKey('Server')) {
            try {
                $domainInfo = Get-ADDomain -Server $ServerParams['Server'] -ErrorAction Stop
            }
            catch {
                throw "Failed to contact Domain Controller '$($ServerParams['Server'])': $($_.Exception.Message)"
            }
        }
        else {
            $domainInfo = Get-ADDomain
        }
        
        # Get all DCs using authoritative DC Locator
        $dcs = @(Get-ADDomainController -Filter * @ServerParams)
        
        if (-not $dcs -or $dcs.Count -eq 0) {
            Write-Finding -Status "WARNING" -Message "No Domain Controllers found for registry assessment"
            return $assessment
        }
        
        Write-Finding -Status "INFO" -Message "Checking KDC registry keys on $($dcs.Count) Domain Controller(s)"
        
        $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
        
        foreach ($dc in $dcs) {
            $dcName = $dc.HostName
            Write-Host "  $([char]0x2022) Querying $dcName..." -ForegroundColor Cyan
            
            try {
                $regValues = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    param($Path)
                    $result = @{ DefaultDomainSupportedEncTypes = $null; RC4DefaultDisablementPhase = $null }
                    try {
                        $val = Get-ItemProperty -Path $Path -Name 'DefaultDomainSupportedEncTypes' -ErrorAction SilentlyContinue
                        if ($val) { $result.DefaultDomainSupportedEncTypes = $val.DefaultDomainSupportedEncTypes }
                    }
                    catch {}
                    try {
                        $val = Get-ItemProperty -Path $Path -Name 'RC4DefaultDisablementPhase' -ErrorAction SilentlyContinue
                        if ($val) { $result.RC4DefaultDisablementPhase = $val.RC4DefaultDisablementPhase }
                    }
                    catch {}
                    $result
                } -ArgumentList $regPath -ErrorAction Stop
                
                $assessment.QueriedDCs += $dcName
                
                $dcDetail = @{
                    Name                           = $dcName
                    DefaultDomainSupportedEncTypes = $regValues.DefaultDomainSupportedEncTypes
                    RC4DefaultDisablementPhase     = $regValues.RC4DefaultDisablementPhase
                }
                $assessment.Details += $dcDetail
                
                # Process DefaultDomainSupportedEncTypes
                if ($null -ne $regValues.DefaultDomainSupportedEncTypes) {
                    $encVal = [int]$regValues.DefaultDomainSupportedEncTypes
                    $assessment.DefaultDomainSupportedEncTypes.Configured = $true
                    $assessment.DefaultDomainSupportedEncTypes.Value = $encVal
                    $assessment.DefaultDomainSupportedEncTypes.Types = Get-EncryptionTypeString -Value $encVal
                    $assessment.DefaultDomainSupportedEncTypes.IncludesRC4 = [bool]($encVal -band 0x4)
                    $assessment.DefaultDomainSupportedEncTypes.IncludesAES = [bool]($encVal -band 0x18)
                    
                    Write-Host "    DefaultDomainSupportedEncTypes: $encVal ($(Get-EncryptionTypeString -Value $encVal))" -ForegroundColor Gray
                }
                
                # Process RC4DefaultDisablementPhase
                if ($null -ne $regValues.RC4DefaultDisablementPhase) {
                    $assessment.RC4DefaultDisablementPhase.Configured = $true
                    $assessment.RC4DefaultDisablementPhase.Value = [int]$regValues.RC4DefaultDisablementPhase
                    
                    Write-Host "    RC4DefaultDisablementPhase: $($regValues.RC4DefaultDisablementPhase)" -ForegroundColor Gray
                }
            }
            catch {
                $assessment.FailedDCs += @{ Name = $dcName; Error = $_.Exception.Message }
                Write-Host "    $([char]0x26A0) Could not query registry on $dcName" -ForegroundColor Yellow
            }
        }
        
        # Assess DefaultDomainSupportedEncTypes
        if ($assessment.DefaultDomainSupportedEncTypes.Configured) {
            if (-not $assessment.DefaultDomainSupportedEncTypes.IncludesAES) {
                $assessment.DefaultDomainSupportedEncTypes.Status = "CRITICAL"
                Write-Finding -Status "CRITICAL" -Message "DefaultDomainSupportedEncTypes does NOT include AES" `
                    -Detail "Value: $($assessment.DefaultDomainSupportedEncTypes.Value) ($($assessment.DefaultDomainSupportedEncTypes.Types))"
            }
            elseif ($assessment.DefaultDomainSupportedEncTypes.IncludesRC4) {
                $assessment.DefaultDomainSupportedEncTypes.Status = "OK"
                Write-Finding -Status "INFO" -Message "DefaultDomainSupportedEncTypes includes RC4 (needed for explicit RC4 exceptions post-July 2026)" `
                    -Detail "Value: $($assessment.DefaultDomainSupportedEncTypes.Value) ($($assessment.DefaultDomainSupportedEncTypes.Types))"
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
                    Write-Finding -Status "WARNING" -Message "RC4DefaultDisablementPhase = 0 (RC4 disablement NOT active)" `
                        -Detail "Set to 1 first to enable KDCSVC audit events 201-209, monitor, then set to 2 for Enforcement (CVE-2026-20833)"
                }
                1 {
                    $assessment.RC4DefaultDisablementPhase.Status = "OK"
                    Write-Finding -Status "OK" -Message "RC4DefaultDisablementPhase = 1 (Audit mode active - KDCSVC events 201-209 enabled)" `
                        -Detail "Monitor KDCSVC events in System log. When no audit events remain, set to 2 for Enforcement (CVE-2026-20833)"
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
            Write-Finding -Status "WARNING" -Message "RC4DefaultDisablementPhase registry key is not set" `
                -Detail "Deploy January 2026+ security updates, then set to 1 to enable KDCSVC audit events (CVE-2026-20833)"
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
