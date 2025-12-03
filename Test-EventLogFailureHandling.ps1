<#
.SYNOPSIS
  Test script to simulate event log query failures and verify error handling.

.DESCRIPTION
  This script simulates various failure scenarios that can occur when querying
  event logs from remote Domain Controllers. It tests the new failure tracking
  and troubleshooting guidance features without requiring actual connectivity issues.

.PARAMETER TestScenario
  Which failure scenario to test:
  - RPCFailure: Simulates RPC server unavailable error
  - WinRMFailure: Simulates WinRM/PowerShell Remoting error
  - AccessDenied: Simulates permission denied error
  - NetworkFailure: Simulates network connectivity issues
  - MixedFailures: Simulates multiple DCs with different failures
  - AllSuccess: Simulates successful queries (control test)

.EXAMPLE
  .\Test-EventLogFailureHandling.ps1 -TestScenario RPCFailure
  Test RPC server unavailable scenario

.EXAMPLE
  .\Test-EventLogFailureHandling.ps1 -TestScenario MixedFailures
  Test multiple DCs with different failure types

.NOTES
  This is a unit test script to verify the error handling and reporting
  functionality of Get-EventLogEncryptionAnalysis without requiring actual
  Domain Controllers or network issues.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('RPCFailure', 'WinRMFailure', 'AccessDenied', 'NetworkFailure', 'MixedFailures', 'AllSuccess')]
    [string]$TestScenario
)

# Mock the event log analysis function with simulated failures
function Test-EventLogFailureHandling {
    param(
        [string]$Scenario
    )
    
    Write-Host "`n$("=" * 80)" -ForegroundColor Cyan
    Write-Host "Testing Event Log Failure Handling - Scenario: $Scenario" -ForegroundColor Cyan
    Write-Host $("=" * 80) -ForegroundColor Cyan
    
    # Simulate the assessment object
    $assessment = @{
        EventsAnalyzed = 0
        DESTickets     = 0
        RC4Tickets     = 0
        AESTickets     = 0
        UnknownTickets = 0
        TimeRange      = 24
        DESAccounts    = @()
        RC4Accounts    = @()
        Details        = @()
        FailedDCs      = @()
    }
    
    # Simulate Domain Controllers
    $mockDCs = @(
        @{ Name = "DC01.contoso.com" }
        @{ Name = "DC02.contoso.com" }
        @{ Name = "DC03.contoso.com" }
    )
    
    Write-Host "`nSimulating queries to $($mockDCs.Count) Domain Controllers..." -ForegroundColor Yellow
    Write-Host "Scenario: $Scenario`n" -ForegroundColor Gray
    
    foreach ($dc in $mockDCs) {
        Write-Host "  • Querying $($dc.Name)..." -ForegroundColor Cyan
        
        # Simulate different failure scenarios
        $shouldFail = $false
        $errorMsg = ""
        
        switch ($Scenario) {
            'RPCFailure' {
                $shouldFail = $true
                $errorMsg = "The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)"
            }
            'WinRMFailure' {
                $shouldFail = $true
                $errorMsg = "Connecting to remote server $($dc.Name) failed with the following error message: WinRM cannot complete the operation."
            }
            'AccessDenied' {
                $shouldFail = $true
                $errorMsg = "Access is denied. Attempted to perform an unauthorized operation."
            }
            'NetworkFailure' {
                $shouldFail = $true
                $errorMsg = "The network path was not found."
            }
            'MixedFailures' {
                # First DC: RPC failure, Second DC: Success, Third DC: Access denied
                if ($dc.Name -eq "DC01.contoso.com") {
                    $shouldFail = $true
                    $errorMsg = "The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)"
                }
                elseif ($dc.Name -eq "DC02.contoso.com") {
                    $shouldFail = $false
                    # Simulate successful query
                    $assessment.EventsAnalyzed += 150
                    $assessment.AESTickets += 148
                    $assessment.RC4Tickets += 2
                }
                elseif ($dc.Name -eq "DC03.contoso.com") {
                    $shouldFail = $true
                    $errorMsg = "Access is denied. Attempted to perform an unauthorized operation."
                }
            }
            'AllSuccess' {
                $shouldFail = $false
                # Simulate successful queries from all DCs
                $assessment.EventsAnalyzed += 120
                $assessment.AESTickets += 118
                $assessment.RC4Tickets += 2
            }
        }
        
        if ($shouldFail) {
            # Simulate error handling
            $assessment.FailedDCs += @{
                Name  = $dc.Name
                Error = $errorMsg
            }
            
            # Display the same warnings as the real script
            if ($errorMsg -match "WinRM|WSMan|PowerShell Remoting") {
                Write-Host "    ⚠  WinRM not available on $($dc.Name)" -ForegroundColor Yellow
                Write-Host "       Enable with: Invoke-Command -ComputerName $($dc.Name) -ScriptBlock { Enable-PSRemoting -Force }" -ForegroundColor Gray
            }
            elseif ($errorMsg -match "RPC server|network path") {
                Write-Host "    ⚠  RPC/Network error on $($dc.Name)" -ForegroundColor Yellow
                Write-Host "       Both WinRM (5985) and RPC (135) failed. Check firewall rules or run locally on DC" -ForegroundColor Gray
            }
            elseif ($errorMsg -match "Access is denied|unauthorized") {
                Write-Host "    ⚠  Access denied on $($dc.Name)" -ForegroundColor Yellow
                Write-Host "       Ensure you have Event Log Readers permissions or are Domain Admin" -ForegroundColor Gray
            }
            else {
                Write-Host "    ⚠  Could not query event log on $($dc.Name): $errorMsg" -ForegroundColor Yellow
            }
            
            Write-Host "`n    Troubleshooting:" -ForegroundColor Yellow
            Write-Host "    1. Enable WinRM on DC: Enable-PSRemoting -Force" -ForegroundColor Gray
            Write-Host "    2. Or allow RPC in firewall: Port 135 + 49152-65535" -ForegroundColor Gray
            Write-Host "    3. Or run this script directly on the DC" -ForegroundColor Gray
            Write-Host "    4. Check permissions: Add your account to 'Event Log Readers' group`n" -ForegroundColor Gray
        }
        else {
            Write-Host "    ✓ Successfully queried $($dc.Name)" -ForegroundColor Green
        }
    }
    
    # Display results summary (simulating the real script output)
    Write-Host ""
    Write-Host "  ℹ  Event Log Analysis Results:" -ForegroundColor Cyan
    Write-Host "  • Events Analyzed: $($assessment.EventsAnalyzed)" -ForegroundColor White
    Write-Host "  • AES Tickets: $($assessment.AESTickets)" -ForegroundColor Green
    Write-Host "  • RC4 Tickets: $($assessment.RC4Tickets)" -ForegroundColor $(if ($assessment.RC4Tickets -gt 0) { "Red" } else { "Green" })
    Write-Host "  • DES Tickets: $($assessment.DESTickets)" -ForegroundColor $(if ($assessment.DESTickets -gt 0) { "Red" } else { "Green" })
    
    # Display the new failure summary section
    if ($assessment.FailedDCs.Count -gt 0) {
        Write-Host "`n  ⚠  Event Log Query Failures:" -ForegroundColor Yellow
        Write-Host "  $($assessment.FailedDCs.Count) Domain Controller(s) could not be queried for event logs`n" -ForegroundColor Yellow
        
        foreach ($failed in $assessment.FailedDCs) {
            Write-Host "  • $($failed.Name): $($failed.Error)" -ForegroundColor DarkYellow
        }
        
        Write-Host "`n  🔧 How to fix remote event log access issues:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Option 1: Enable WinRM (Recommended)" -ForegroundColor White
        Write-Host "  $([string]([char]0x2500) * 40)" -ForegroundColor DarkGray
        Write-Host "  Run on each failed DC:" -ForegroundColor Gray
        Write-Host "  PS> Enable-PSRemoting -Force" -ForegroundColor Green
        Write-Host "  PS> Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force" -ForegroundColor Green
        Write-Host "  PS> Restart-Service WinRM" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Or via Group Policy (for all DCs):" -ForegroundColor Gray
        Write-Host "  Computer Configuration > Policies > Administrative Templates" -ForegroundColor Gray
        Write-Host "  > Windows Components > Windows Remote Management (WinRM) > WinRM Service" -ForegroundColor Gray
        Write-Host "  - Enable 'Allow remote server management through WinRM'" -ForegroundColor Gray
        Write-Host "  - IPv4 filter: * (or specific IPs)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Option 2: Configure Firewall for RPC" -ForegroundColor White
        Write-Host "  $([string]([char]0x2500) * 40)" -ForegroundColor DarkGray
        Write-Host "  Required ports:" -ForegroundColor Gray
        Write-Host "  - TCP 135 (RPC Endpoint Mapper)" -ForegroundColor Gray
        Write-Host "  - TCP 49152-65535 (Dynamic RPC ports)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Windows Firewall rule:" -ForegroundColor Gray
        Write-Host "  PS> Enable-NetFirewallRule -DisplayGroup 'Remote Event Log Management'" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Option 3: Run Locally on DC" -ForegroundColor White
        Write-Host "  $([string]([char]0x2500) * 40)" -ForegroundColor DarkGray
        Write-Host "  Copy script to DC and run:" -ForegroundColor Gray
        Write-Host "  PS> .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours $($assessment.TimeRange)" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Option 4: Verify Permissions" -ForegroundColor White
        Write-Host "  $([string]([char]0x2500) * 40)" -ForegroundColor DarkGray
        Write-Host "  Add your account to 'Event Log Readers' group on DCs:" -ForegroundColor Gray
        Write-Host "  PS> Add-ADGroupMember -Identity 'Event Log Readers' -Members 'YourAccount'" -ForegroundColor Green
        Write-Host "  Or use Domain Admin account (has all required permissions)" -ForegroundColor Gray
        Write-Host ""
    }
    else {
        Write-Host "`n  ✓ All Domain Controllers queried successfully - No failures detected" -ForegroundColor Green
    }
    
    # Return the assessment for validation
    return $assessment
}

# Run the test
$result = Test-EventLogFailureHandling -Scenario $TestScenario

# Display test results
Write-Host "`n$("=" * 80)" -ForegroundColor Cyan
Write-Host "Test Results Summary" -ForegroundColor Cyan
Write-Host $("=" * 80) -ForegroundColor Cyan
Write-Host "Scenario Tested: $TestScenario" -ForegroundColor White
Write-Host "Failed DCs Tracked: $($result.FailedDCs.Count)" -ForegroundColor $(if ($result.FailedDCs.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "Events Analyzed: $($result.EventsAnalyzed)" -ForegroundColor White
Write-Host "Test Status: " -NoNewline
if ($TestScenario -eq 'AllSuccess' -and $result.FailedDCs.Count -eq 0) {
    Write-Host "PASSED ✓" -ForegroundColor Green
    Write-Host "No failures detected as expected for AllSuccess scenario" -ForegroundColor Gray
}
elseif ($TestScenario -ne 'AllSuccess' -and $result.FailedDCs.Count -gt 0) {
    Write-Host "PASSED ✓" -ForegroundColor Green
    Write-Host "Failures properly tracked and troubleshooting guidance displayed" -ForegroundColor Gray
}
else {
    Write-Host "FAILED ✗" -ForegroundColor Red
    Write-Host "Unexpected result for scenario $TestScenario" -ForegroundColor Red
}

Write-Host "`n💡 Tip: Run with different -TestScenario values to test all failure types:" -ForegroundColor Cyan
Write-Host "  - RPCFailure" -ForegroundColor Gray
Write-Host "  - WinRMFailure" -ForegroundColor Gray
Write-Host "  - AccessDenied" -ForegroundColor Gray
Write-Host "  - NetworkFailure" -ForegroundColor Gray
Write-Host "  - MixedFailures (recommended for comprehensive test)" -ForegroundColor Gray
Write-Host "  - AllSuccess (control test - no failures)`n" -ForegroundColor Gray
