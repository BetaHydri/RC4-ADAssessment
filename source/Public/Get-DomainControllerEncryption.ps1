function Get-DomainControllerEncryption {
    <#
    .SYNOPSIS
        Assesses the Kerberos encryption configuration on all Domain Controllers in a domain.

    .DESCRIPTION
        Queries Active Directory for all Domain Controllers and reads their
        msDS-SupportedEncryptionTypes attribute to determine whether each DC is configured for
        AES, RC4, DES, or the platform default. Also checks Group Policy for domain-level
        encryption type settings. Returns a detailed hashtable with per-DC findings and
        aggregate counts.

    .PARAMETER ServerParams
        A hashtable of parameters passed through to Active Directory cmdlets. Supports a
        'Server' key to target a specific Domain Controller.

    .EXAMPLE
        $params = @{ Server = 'dc01.contoso.com' }
        $result = Get-DomainControllerEncryption -ServerParams $params
        $result.DESConfigured
    #>
    param(
        [hashtable]$ServerParams
    )
    
    Write-Section "Domain Controller Encryption Configuration"
    
    $assessment = @{
        TotalDCs           = 0
        AESConfigured      = 0
        RC4Configured      = 0
        DESConfigured      = 0
        NotConfigured      = 0
        AzureADKerberos    = $null  # Entra Kerberos proxy object (not a real DC)
        Details            = @()
        GPOConfigured      = $false
        GPOEncryptionTypes = $null
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
        $dcOU = "OU=Domain Controllers,$($domainInfo.DistinguishedName)"
        
        Write-Finding -Status "INFO" -Message "Analyzing domain: $($domainInfo.DNSRoot)"
        
        # Get all domain controllers using authoritative DC Locator (queries Configuration partition)
        $dcObjects = @(Get-ADDomainController -Filter * @ServerParams)
        
        $assessment.TotalDCs = $dcObjects.Count
        
        Write-Finding -Status "INFO" -Message "Found $($assessment.TotalDCs) Domain Controller(s)"
        
        # Check for AzureADKerberos (Entra Kerberos proxy) in DC OU - not a real DC
        try {
            $azureADKerberos = Get-ADComputer -Identity 'AzureADKerberos' -Properties msDS-SupportedEncryptionTypes @ServerParams -ErrorAction SilentlyContinue
            if ($azureADKerberos) {
                $encValue = $azureADKerberos.'msDS-SupportedEncryptionTypes'
                $assessment.AzureADKerberos = @{
                    Name              = 'AzureADKerberos'
                    EncryptionValue   = $encValue
                    EncryptionTypes   = Get-EncryptionTypeString -Value $encValue
                    Status            = 'Entra Kerberos Proxy (Managed by Microsoft Entra ID)'
                    IsAzureADKerberos = $true
                }
                Write-Finding -Status "INFO" -Message "AzureADKerberos object detected (Entra Kerberos proxy - not a real DC, excluded from DC counts)"
            }
        }
        catch {
            # AzureADKerberos object not found - this is normal
        }
        
        # Analyze each DC - read computer object properties for encryption assessment
        foreach ($dc in $dcObjects) {
            $dcComputer = Get-ADComputer $dc.ComputerObjectDN -Properties msDS-SupportedEncryptionTypes, OperatingSystem @ServerParams
            $encValue = $dcComputer.'msDS-SupportedEncryptionTypes'
            $encTypes = Get-EncryptionTypeString -Value $encValue
            
            $dcInfo = @{
                Name            = $dc.Name
                EncryptionValue = $encValue
                EncryptionTypes = $encTypes
                OperatingSystem = $dcComputer.OperatingSystem
                Status          = "Unknown"
            }
            
            if (-not $encValue -or $encValue -eq 0) {
                $assessment.NotConfigured++
                $dcInfo.Status = "Not Configured (Inherits from GPO)"
            }
            elseif ($encValue -band 0x18) {
                # AES128 or AES256
                $assessment.AESConfigured++
                $dcInfo.Status = "AES Configured"
                
                if ($encValue -band 0x4) {
                    # Also has RC4
                    $assessment.RC4Configured++
                    $dcInfo.Status += " + RC4"
                }
                if ($encValue -band 0x3) {
                    # Also has DES
                    $assessment.DESConfigured++
                    $dcInfo.Status += " + DES"
                }
            }
            elseif ($encValue -band 0x4) {
                # RC4 only
                $assessment.RC4Configured++
                $dcInfo.Status = "RC4 Only"
            }
            elseif ($encValue -band 0x3) {
                # DES only
                $assessment.DESConfigured++
                $dcInfo.Status = "DES Only"
            }
            
            $assessment.Details += $dcInfo
        }
        
        # Check GPO configuration
        Write-Host "`n  Checking GPO Kerberos encryption policy..." -ForegroundColor Cyan
        
        try {
            # Try to get GPO inheritance for DC OU via GroupPolicy module
            $gpoInheritance = Get-GPInheritance -Target $dcOU -Domain $domainInfo.DNSRoot @ServerParams -ErrorAction Stop
            
            if ($gpoInheritance -and $gpoInheritance.GpoLinks) {
                foreach ($gpoLink in $gpoInheritance.GpoLinks) {
                    # Guard: on broken GroupPolicy assemblies, GpoLinks may be strings instead of objects
                    if ($gpoLink -is [string]) { continue }
                    if ($gpoLink.Enabled) {
                        $gpoReport = Get-GPOReport -Guid $gpoLink.GpoId -ReportType Xml -Domain $domainInfo.DNSRoot @ServerParams -ErrorAction SilentlyContinue
                        
                        if ($gpoReport -and $gpoReport -match "Configure encryption types allowed for Kerberos") {
                            $assessment.GPOConfigured = $true
                            
                            # Extract encryption value from GPO
                            if ($gpoReport -match 'name="Configure encryption types allowed for Kerberos".*?<decimal value="(\d+)"') {
                                $assessment.GPOEncryptionTypes = [int]$matches[1]
                            }
                            
                            Write-Finding -Status "OK" -Message "GPO '$($gpoLink.DisplayName)' configures Kerberos encryption" `
                                -Detail "Encryption types: $(Get-EncryptionTypeString -Value $assessment.GPOEncryptionTypes)"
                            break
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "GroupPolicy module failed: $($_.Exception.Message)"
        }
        
        # Fallback: If GroupPolicy module produced no results (broken assembly, serialization issues, etc.)
        # read the gPLink AD attribute on the DC OU and parse SYSVOL GptTmpl.inf directly
        if (-not $assessment.GPOConfigured) {
            try {
                $dcOUObj = Get-ADObject -Identity $dcOU -Properties gPLink @ServerParams -ErrorAction Stop
                if ($dcOUObj.gPLink) {
                    # Parse gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;flags]
                    # flags: 0=enabled, 1=disabled, 2=enforced, 3=disabled+enforced
                    $linkMatches = [regex]::Matches($dcOUObj.gPLink, 'LDAP://cn=(\{[0-9A-Fa-f\-]+\}),cn=policies,cn=system,[^;]*;(\d+)')
                    foreach ($linkMatch in $linkMatches) {
                        $gpoGuid = $linkMatch.Groups[1].Value.ToUpper()
                        $linkFlags = [int]$linkMatch.Groups[2].Value
                        # Skip disabled links (bit 0 set = disabled)
                        if ($linkFlags -band 1) { continue }
                        
                        $sysvolPath = "\\$($domainInfo.DNSRoot)\SYSVOL\$($domainInfo.DNSRoot)\Policies\$gpoGuid\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                        if (Test-Path -LiteralPath $sysvolPath) {
                            $gptTmplContent = Get-Content -LiteralPath $sysvolPath -Raw -ErrorAction Stop
                            if ($gptTmplContent -match 'SupportedEncryptionTypes\s*=\s*4\s*,\s*(\d+)') {
                                $assessment.GPOConfigured = $true
                                $assessment.GPOEncryptionTypes = [int]$matches[1]
                                
                                # Try to resolve GPO display name
                                $gpoDisplayName = $gpoGuid
                                try {
                                    $gpoADObj = Get-ADObject -Filter "objectClass -eq 'groupPolicyContainer'" -SearchBase "CN=Policies,CN=System,$($domainInfo.DistinguishedName)" -Properties DisplayName @ServerParams |
                                    Where-Object { $_.Name -eq $gpoGuid }
                                    if ($gpoADObj) { $gpoDisplayName = $gpoADObj.DisplayName }
                                }
                                catch { }
                                
                                Write-Finding -Status "OK" -Message "GPO '$gpoDisplayName' configures Kerberos encryption (detected via SYSVOL)" `
                                    -Detail "Encryption types: $(Get-EncryptionTypeString -Value $assessment.GPOEncryptionTypes)"
                                break
                            }
                        }
                    }
                }
            }
            catch {
                Write-Verbose "SYSVOL fallback failed: $($_.Exception.Message)"
            }
        }
        
        # Display summary
        Write-Host ""
        Write-Finding -Status "INFO" -Message "Domain Controller Summary:"
        Write-Host "  $([char]0x2022) Total DCs: $($assessment.TotalDCs)" -ForegroundColor White
        Write-Host "  $([char]0x2022) AES Configured: $($assessment.AESConfigured)" -ForegroundColor $(if ($assessment.AESConfigured -eq $assessment.TotalDCs) { "Green" } else { "Yellow" })
        Write-Host "  $([char]0x2022) RC4 Configured: $($assessment.RC4Configured)" -ForegroundColor $(if ($assessment.RC4Configured -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  $([char]0x2022) DES Configured: $($assessment.DESConfigured)" -ForegroundColor $(if ($assessment.DESConfigured -gt 0) { "Red" } else { "Green" })
        Write-Host "  $([char]0x2022) Not Configured (GPO Inherited): $($assessment.NotConfigured)" -ForegroundColor Cyan
        if ($assessment.AzureADKerberos) {
            Write-Host "  $([char]0x2022) AzureADKerberos (Entra proxy): Excluded from DC counts (managed by Entra ID)" -ForegroundColor DarkCyan
        }
        
        # Display individual DC details
        if ($assessment.Details.Count -gt 0) {
            Write-Host "`n  Individual DC Status:" -ForegroundColor Cyan
            foreach ($dcInfo in $assessment.Details) {
                $statusColor = switch -Regex ($dcInfo.Status) {
                    "AES Configured$" { "Green" }
                    "RC4" { "Yellow" }
                    "DES" { "Red" }
                    default { "Cyan" }
                }
                Write-Host "    $([char]0x2022) $($dcInfo.Name): $($dcInfo.Status)" -ForegroundColor $statusColor
                if ($dcInfo.EncryptionValue) {
                    Write-Host "      Types: $($dcInfo.EncryptionTypes)" -ForegroundColor Gray
                }
            }
        }
        
        # Assessment
        if ($assessment.GPOConfigured -and ($assessment.GPOEncryptionTypes -band 0x18)) {
            Write-Finding -Status "OK" -Message "Domain Controllers are configured for AES encryption via GPO"
            if ($assessment.NotConfigured -gt 0) {
                Write-Finding -Status "INFO" -Message "$($assessment.NotConfigured) DC(s) inherit AES settings from GPO (this is normal)"
            }
        }
        elseif ($assessment.AESConfigured -eq $assessment.TotalDCs -and $assessment.TotalDCs -gt 0) {
            Write-Finding -Status "OK" -Message "All Domain Controllers have AES encryption configured"
        }
        elseif ($assessment.TotalDCs -gt 0) {
            Write-Finding -Status "WARNING" -Message "Not all Domain Controllers have AES encryption configured"
        }
        
        if ($assessment.DESConfigured -gt 0) {
            Write-Finding -Status "CRITICAL" -Message "$($assessment.DESConfigured) DC(s) have DES encryption enabled - immediate remediation required"
        }
        
        if ($assessment.RC4Configured -gt 0) {
            Write-Finding -Status "WARNING" -Message "$($assessment.RC4Configured) DC(s) have RC4 encryption enabled"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        # Extract DC name from error message if it mentions "Failed to contact Domain Controller"
        if ($errorMsg -match "Failed to contact Domain Controller '([^']+)'") {
            Write-Finding -Status "CRITICAL" -Message $errorMsg
        }
        elseif ($ServerParams.ContainsKey('Server')) {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing Domain Controllers (Attempted DC: $($ServerParams['Server'])): $errorMsg"
        }
        else {
            Write-Finding -Status "CRITICAL" -Message "Error analyzing Domain Controllers: $errorMsg"
        }
    }
    
    return $assessment
}
