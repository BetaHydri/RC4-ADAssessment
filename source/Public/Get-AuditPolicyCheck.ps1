function Get-AuditPolicyCheck {
    param(
        [hashtable]$ServerParams
    )
    
    Write-Section "Kerberos Audit Policy Verification"
    
    $assessment = @{
        KerberosAuthServiceEnabled = $null    # $true, $false, or $null if unknown
        KerberosTicketOpsEnabled   = $null
        Status                     = "Unknown"
        QueriedDC                  = $null
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
        
        # Query first available DC using authoritative DC Locator
        $dc = Get-ADDomainController -Filter * @ServerParams | Select-Object -First 1
        
        if (-not $dc) {
            Write-Finding -Status "WARNING" -Message "No Domain Controller found for audit policy check"
            return $assessment
        }
        
        $dcName = $dc.HostName
        $assessment.QueriedDC = $dcName
        
        Write-Finding -Status "INFO" -Message "Checking Kerberos audit policy on $dcName"
        
        try {
            $auditResult = Invoke-Command -ComputerName $dcName -ScriptBlock {
                $output = auditpol /get /subcategory:"Kerberos Authentication Service" 2>&1
                $authService = $output | Out-String
                $output2 = auditpol /get /subcategory:"Kerberos Service Ticket Operations" 2>&1
                $ticketOps = $output2 | Out-String
                @{
                    AuthService = $authService
                    TicketOps   = $ticketOps
                }
            } -ErrorAction Stop
            
            # Parse audit policy results
            $assessment.KerberosAuthServiceEnabled = $auditResult.AuthService -match 'Success and Failure|Success|Failure'
            $assessment.KerberosTicketOpsEnabled = $auditResult.TicketOps -match 'Success and Failure|Success|Failure'
            
            if ($assessment.KerberosAuthServiceEnabled -and $assessment.KerberosTicketOpsEnabled) {
                $assessment.Status = "OK"
                Write-Finding -Status "OK" -Message "Kerberos auditing is enabled (Authentication Service + Ticket Operations)"
            }
            elseif (-not $assessment.KerberosAuthServiceEnabled -and -not $assessment.KerberosTicketOpsEnabled) {
                $assessment.Status = "CRITICAL"
                Write-Finding -Status "CRITICAL" -Message "Kerberos auditing is NOT enabled - event log analysis will return no results" `
                    -Detail "Enable via: auditpol /set /subcategory:""Kerberos Authentication Service"" /success:enable /failure:enable"
                Write-Host "    Also run: auditpol /set /subcategory:""Kerberos Service Ticket Operations"" /success:enable /failure:enable" -ForegroundColor Gray
            }
            else {
                $assessment.Status = "WARNING"
                if (-not $assessment.KerberosAuthServiceEnabled) {
                    Write-Finding -Status "WARNING" -Message "Kerberos Authentication Service auditing is NOT enabled"
                }
                if (-not $assessment.KerberosTicketOpsEnabled) {
                    Write-Finding -Status "WARNING" -Message "Kerberos Service Ticket Operations auditing is NOT enabled"
                }
            }
        }
        catch {
            $assessment.Status = "UNKNOWN"
            Write-Finding -Status "WARNING" -Message "Could not check audit policy on $dcName`: $($_.Exception.Message)" `
                -Detail "Verify manually: auditpol /get /subcategory:""Kerberos Authentication Service"""
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $assessment.Status = "UNKNOWN"
        Write-Finding -Status "WARNING" -Message "Error checking audit policy: $errorMsg"
    }
    
    return $assessment
}
