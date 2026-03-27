function Get-TrustEncryptionAssessment {
    <#
    .SYNOPSIS
        Assesses Kerberos encryption configuration on Active Directory trust relationships.

    .DESCRIPTION
        Queries Active Directory for all domain and forest trust objects and evaluates their
        msDS-SupportedEncryptionTypes attribute. Following the post-November 2022 behaviour,
        an empty or zero value is treated as AES default. Trusts explicitly configured for
        RC4 or DES are flagged as risks. Returns a detailed hashtable with per-trust findings
        and aggregate counts.

    .PARAMETER ServerParams
        A hashtable of parameters passed through to Active Directory cmdlets. Supports a
        'Server' key to target a specific Domain Controller.

    .EXAMPLE
        $params = @{ Server = 'dc01.contoso.com' }
        $result = Get-TrustEncryptionAssessment -ServerParams $params
        $result.RC4Risk
    #>
    param(
        [hashtable]$ServerParams
    )
    
    Write-Section "Trust Encryption Assessment (Post-November 2022 Logic)"
    
    $assessment = @{
        TotalTrusts = 0
        ExplicitAES = 0
        DefaultAES  = 0  # Post-Nov 2022: Empty/0 = AES default
        RC4Risk     = 0
        DESRisk     = 0
        Details     = @()
    }
    
    try {
        # Get domain info - ensure we query the correct domain
        if ($ServerParams.ContainsKey('Server')) {
            Write-Verbose "Attempting to contact DC: $($ServerParams['Server'])"
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
        $trusts = Get-ADTrust -Filter * @ServerParams -Properties msDS-SupportedEncryptionTypes, TrustDirection, TrustType
        
        if (-not $trusts) {
            Write-Finding -Status "INFO" -Message "No trusts found in domain: $($domainInfo.DNSRoot)"
            return $assessment
        }
        
        $assessment.TotalTrusts = if ($trusts -is [array]) { $trusts.Count } else { 1 }
        Write-Finding -Status "INFO" -Message "Found $($assessment.TotalTrusts) trust(s)"
        
        foreach ($trust in $trusts) {
            $encValue = $trust.'msDS-SupportedEncryptionTypes'
            $encTypes = Get-EncryptionTypeString -Value $encValue
            
            $trustInfo = @{
                Name                 = $trust.Name
                Direction            = $trust.TrustDirection
                Type                 = $trust.TrustType
                EncryptionValue      = $encValue
                EncryptionTypes      = $encTypes
                Status               = "Unknown"
                PostNov2022Compliant = $false
            }
            
            # Post-November 2022 logic: Trusts default to AES when not set
            if (-not $encValue -or $encValue -eq 0) {
                $assessment.DefaultAES++
                $trustInfo.Status = "AES (Default - Post-Nov 2022)"
                $trustInfo.PostNov2022Compliant = $true
                Write-Finding -Status "OK" -Message "Trust '$($trust.Name)': Uses AES by default (msDS-SupportedEncryptionTypes not set)"
            }
            elseif ($encValue -band 0x18) {
                # Explicit AES
                $assessment.ExplicitAES++
                $trustInfo.Status = "AES (Explicitly Configured)"
                $trustInfo.PostNov2022Compliant = $true
                
                if ($encValue -band 0x4) {
                    # Also has RC4
                    $assessment.RC4Risk++
                    $trustInfo.Status += " + RC4 Enabled"
                    Write-Finding -Status "WARNING" -Message "Trust '$($trust.Name)': AES configured but RC4 also enabled" `
                        -Detail "Encryption: $encTypes"
                }
                else {
                    Write-Finding -Status "OK" -Message "Trust '$($trust.Name)': AES explicitly configured"
                }
                
                if ($encValue -band 0x3) {
                    # Also has DES
                    $assessment.DESRisk++
                    $trustInfo.Status += " + DES Enabled"
                    Write-Finding -Status "CRITICAL" -Message "Trust '$($trust.Name)': DES encryption enabled" `
                        -Detail "Encryption: $encTypes"
                }
            }
            elseif ($encValue -band 0x4) {
                # RC4 only
                $assessment.RC4Risk++
                $trustInfo.Status = "RC4 Only"
                Write-Finding -Status "WARNING" -Message "Trust '$($trust.Name)': RC4 only - consider removing explicit setting to use AES default"
            }
            elseif ($encValue -band 0x3) {
                # DES only
                $assessment.DESRisk++
                $trustInfo.Status = "DES Only"
                Write-Finding -Status "CRITICAL" -Message "Trust '$($trust.Name)': DES only - immediate remediation required"
            }
            
            $assessment.Details += $trustInfo
        }
        
        # Summary
        Write-Host ""
        Write-Finding -Status "INFO" -Message "Trust Assessment Summary:"
        Write-Host "  $([char]0x2022) Total Trusts: $($assessment.TotalTrusts)" -ForegroundColor White
        Write-Host "  $([char]0x2022) AES Default (not set): $($assessment.DefaultAES)" -ForegroundColor Green
        Write-Host "  $([char]0x2022) AES Explicit: $($assessment.ExplicitAES)" -ForegroundColor Green
        Write-Host "  $([char]0x2022) RC4 Risk: $($assessment.RC4Risk)" -ForegroundColor $(if ($assessment.RC4Risk -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  $([char]0x2022) DES Risk: $($assessment.DESRisk)" -ForegroundColor $(if ($assessment.DESRisk -gt 0) { "Red" } else { "Green" })
        
        Write-Host "`n  $([System.Char]::ConvertFromUtf32(0x1F4D8)) Post-November 2022 Update:" -ForegroundColor Cyan
        Write-Host "  When msDS-SupportedEncryptionTypes is not set (0 or empty) on trusts," -ForegroundColor Gray
        Write-Host "  they default to AES encryption. No action needed for these trusts." -ForegroundColor Gray
    }
    catch {
        $errorMsg = $_.Exception.Message
        # Extract DC name from error message if it mentions "Failed to contact Domain Controller"
        if ($errorMsg -match "Failed to contact Domain Controller '([^']+)'") {
            Write-Finding -Status "CRITICAL" -Message $errorMsg
        }
        elseif ($ServerParams.ContainsKey('Server')) {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing trusts (Attempted DC: $($ServerParams['Server'])): $errorMsg"
        }
        else {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing trusts: $errorMsg"
        }
    }
    
    return $assessment
}
