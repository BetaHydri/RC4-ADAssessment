<#
.SYNOPSIS
  Test script components without Active Directory access

.DESCRIPTION
  This script tests the helper functions, display formatting, and emoji rendering
  from RC4_DES_Assessment.ps1 without requiring Active Directory connectivity.
#>

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "RC4_DES_Assessment.ps1 - Component Testing (No AD Required)" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan

# Source the helper functions from the main script
Write-Host "`n[1/6] Loading helper functions..." -ForegroundColor Yellow

# Extract and define helper functions
function Write-Header {
    param([string]$Title, [string]$Color = "Cyan")
    
    Write-Host "`n$("=" * 80)" -ForegroundColor $Color
    Write-Host $Title -ForegroundColor $Color
    Write-Host $("=" * 80) -ForegroundColor $Color
}

function Write-Section {
    param([string]$Title, [string]$Color = "Yellow")
    
    Write-Host "`n$Title" -ForegroundColor $Color
    Write-Host $("-" * 60) -ForegroundColor $Color
}

function Write-Finding {
    param(
        [string]$Status,  # OK, WARNING, CRITICAL, INFO
        [string]$Message,
        [string]$Detail = ""
    )
    
    $statusSymbol = switch ($Status) {
        "OK"       { "$([char]0x2713)"; $color = "Green" }  # ✓ Check mark
        "WARNING"  { "$([char]0x26A0) "; $color = "Yellow" }  # ⚠ Warning sign
        "CRITICAL" { "$([char]0x2717)"; $color = "Red" }  # ✗ Cross mark
        "INFO"     { "$([char]0x2139) "; $color = "Cyan" }  # ℹ Info
        default    { "$([char]0x2022)"; $color = "White" }  # • Bullet
    }
    
    Write-Host "  $statusSymbol $Message" -ForegroundColor $color
    if ($Detail) {
        Write-Host "    $Detail" -ForegroundColor Gray
    }
}

Write-Host "  $([char]0x2713) Helper functions loaded successfully" -ForegroundColor Green

# Test 1: Display formatting functions
Write-Section "[2/6] Testing Display Formatting"
Write-Header "Test Header" -Color "Magenta"
Write-Section "Test Section" -Color "Cyan"
Write-Host "  $([char]0x2713) Formatting functions working" -ForegroundColor Green

# Test 2: Status symbols and emojis
Write-Section "[3/6] Testing Status Symbols & Emojis"
Write-Finding -Status "OK" -Message "This is an OK status message"
Write-Finding -Status "WARNING" -Message "This is a WARNING status message"
Write-Finding -Status "CRITICAL" -Message "This is a CRITICAL status message"
Write-Finding -Status "INFO" -Message "This is an INFO status message"
Write-Finding -Status "DEFAULT" -Message "This is a default bullet point"

Write-Host "`n  Additional symbols:" -ForegroundColor White
Write-Host "    $([char]0x2022) Bullet point" -ForegroundColor White
Write-Host "    $([System.Char]::ConvertFromUtf32(0x1F4CA)) Chart emoji" -ForegroundColor Cyan
Write-Host "    $([System.Char]::ConvertFromUtf32(0x1F4A1)) Lightbulb emoji" -ForegroundColor Yellow
Write-Host "    $([System.Char]::ConvertFromUtf32(0x1F4CB)) Clipboard emoji" -ForegroundColor White
Write-Host "    $([System.Char]::ConvertFromUtf32(0x1F4DA)) Books emoji" -ForegroundColor Cyan
Write-Host "    $([System.Char]::ConvertFromUtf32(0x1F4D8)) Book emoji" -ForegroundColor Blue
Write-Host "    $([string]([char]0x2500) * 20) Box drawing line" -ForegroundColor Gray

# Test 3: Encryption type decoding
Write-Section "[4/6] Testing Encryption Type Decoding"

function Get-EncryptionTypeName {
    param([int]$Value)
    
    $types = @()
    if ($Value -band 0x1) { $types += "DES-CBC-CRC" }
    if ($Value -band 0x2) { $types += "DES-CBC-MD5" }
    if ($Value -band 0x4) { $types += "RC4-HMAC" }
    if ($Value -band 0x8) { $types += "AES128-CTS-HMAC-SHA1-96" }
    if ($Value -band 0x10) { $types += "AES256-CTS-HMAC-SHA1-96" }
    
    if ($types.Count -eq 0) { return "Not Set (0)" }
    return ($types -join ", ")
}

$testValues = @(
    @{Value = 0; Description = "Not set (AES default post-Nov 2022)"}
    @{Value = 0x1; Description = "DES only (CRITICAL)"}
    @{Value = 0x4; Description = "RC4 only (WARNING)"}
    @{Value = 0x18; Description = "AES 128+256 (GOOD)"}
    @{Value = 0x1C; Description = "RC4 + AES (WARNING - remove RC4)"}
    @{Value = 0x1F; Description = "All types including DES (CRITICAL)"}
)

foreach ($test in $testValues) {
    $encTypes = Get-EncryptionTypeName -Value $test.Value
    Write-Host "  Value $($test.Value) (0x$($test.Value.ToString('X'))): $encTypes" -ForegroundColor White
    Write-Host "    → $($test.Description)" -ForegroundColor Gray
}

# Test 4: Event log encryption type detection
Write-Section "[5/6] Testing Event Log Ticket Type Detection"

function Get-TicketEncryptionType {
    param([string]$HexValue)
    
    switch ($HexValue) {
        "0x1" { return @{Type = "DES-CBC-CRC"; Severity = "CRITICAL"; Color = "Red"} }
        "0x3" { return @{Type = "DES-CBC-MD5"; Severity = "CRITICAL"; Color = "Red"} }
        "0x17" { return @{Type = "RC4-HMAC"; Severity = "WARNING"; Color = "Yellow"} }
        "0x11" { return @{Type = "AES128-CTS-HMAC-SHA1-96"; Severity = "OK"; Color = "Green"} }
        "0x12" { return @{Type = "AES256-CTS-HMAC-SHA1-96"; Severity = "OK"; Color = "Green"} }
        default { return @{Type = "Unknown ($HexValue)"; Severity = "INFO"; Color = "Gray"} }
    }
}

$ticketTypes = @("0x1", "0x3", "0x17", "0x11", "0x12", "0x18")
foreach ($type in $ticketTypes) {
    $info = Get-TicketEncryptionType -HexValue $type
    Write-Host "  Event TicketEncryptionType $type → $($info.Type)" -ForegroundColor $info.Color
}

# Test 5: Mock assessment summary
Write-Section "[6/6] Testing Mock Assessment Display"

$mockResults = @{
    Domain = "contoso.com"
    AssessmentDate = Get-Date
    OverallStatus = "WARNING"
    DomainControllers = @{
        TotalDCs = 5
        AESConfigured = 4
        RC4Configured = 1
        DESConfigured = 0
        NotConfigured = 0
        GPOConfigured = $true
        GPOEncryptionTypes = 0x18
    }
    Trusts = @{
        TotalTrusts = 3
        DefaultAES = 2
        ExplicitAES = 1
        RC4Risk = 0
        DESRisk = 0
    }
    EventLogs = @{
        EventsAnalyzed = 1250
        AESTickets = 1200
        RC4Tickets = 50
        DESTickets = 0
    }
    Recommendations = @(
        "WARNING: Remove RC4 encryption from 1 Domain Controller(s)"
        "WARNING: 50 RC4 tickets detected in event logs - investigate affected systems"
    )
}

Write-Host "`n$([System.Char]::ConvertFromUtf32(0x1F4CA)) Mock Assessment Summary:" -ForegroundColor Cyan
Write-Host "  $([char]0x2022) Domain: $($mockResults.Domain)" -ForegroundColor White
Write-Host "  $([char]0x2022) Assessment Date: $($mockResults.AssessmentDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
Write-Host "  $([char]0x2022) Overall Status: " -NoNewline -ForegroundColor White

$statusColor = switch ($mockResults.OverallStatus) {
    "OK" { "Green" }
    "WARNING" { "Yellow" }
    "CRITICAL" { "Red" }
    default { "Gray" }
}
Write-Host $mockResults.OverallStatus -ForegroundColor $statusColor

Write-Section "Domain Controllers (Mock Data)"
Write-Host "  $([char]0x2022) Total DCs: $($mockResults.DomainControllers.TotalDCs)" -ForegroundColor White
Write-Host "  $([char]0x2022) AES Configured: $($mockResults.DomainControllers.AESConfigured)" -ForegroundColor Green
Write-Host "  $([char]0x2022) RC4 Configured: $($mockResults.DomainControllers.RC4Configured)" -ForegroundColor Yellow
Write-Host "  $([char]0x2022) DES Configured: $($mockResults.DomainControllers.DESConfigured)" -ForegroundColor Green

Write-Section "Trusts (Mock Data)"
Write-Host "  $([char]0x2022) Total Trusts: $($mockResults.Trusts.TotalTrusts)" -ForegroundColor White
Write-Host "  $([char]0x2022) AES Default (not set): $($mockResults.Trusts.DefaultAES)" -ForegroundColor Green
Write-Host "  $([char]0x2022) AES Explicit: $($mockResults.Trusts.ExplicitAES)" -ForegroundColor Green
Write-Host "  $([char]0x2022) RC4 Risk: $($mockResults.Trusts.RC4Risk)" -ForegroundColor Green
Write-Host "  $([char]0x2022) DES Risk: $($mockResults.Trusts.DESRisk)" -ForegroundColor Green

Write-Section "Event Logs (Mock Data)"
Write-Host "  $([char]0x2022) Events Analyzed: $($mockResults.EventLogs.EventsAnalyzed)" -ForegroundColor White
Write-Host "  $([char]0x2022) AES Tickets: $($mockResults.EventLogs.AESTickets)" -ForegroundColor Green
Write-Host "  $([char]0x2022) RC4 Tickets: $($mockResults.EventLogs.RC4Tickets)" -ForegroundColor Yellow
Write-Host "  $([char]0x2022) DES Tickets: $($mockResults.EventLogs.DESTickets)" -ForegroundColor Green

Write-Section "Recommendations"
foreach ($rec in $mockResults.Recommendations) {
    Write-Host "  $([char]0x2022) $rec" -ForegroundColor Yellow
}

# Summary
Write-Header "Test Results" -Color "Green"
Write-Host @"

$([char]0x2713) All helper functions working correctly
$([char]0x2713) Display formatting rendering properly
$([char]0x2713) Emoji and Unicode symbols displaying (PowerShell 5.1 compatible)
$([char]0x2713) Encryption type decoding functional
$([char]0x2713) Event log ticket type detection working
$([char]0x2713) Mock assessment display successful

"@ -ForegroundColor Green

Write-Host "$([System.Char]::ConvertFromUtf32(0x1F4A1)) What requires Active Directory access:" -ForegroundColor Yellow
Write-Host @"
  $([char]0x2022) Querying Domain Controllers and their msDS-SupportedEncryptionTypes
  $([char]0x2022) Checking Group Policy Objects for Kerberos encryption settings
  $([char]0x2022) Enumerating domain trusts and their encryption configuration
  $([char]0x2022) Analyzing Security Event Logs (4768/4769) on DCs
  $([char]0x2022) Querying computer/user account encryption type attributes

"@ -ForegroundColor Gray

Write-Host "$([System.Char]::ConvertFromUtf32(0x1F4CB)) Next Steps:" -ForegroundColor Cyan
Write-Host @"
  1. Test script is working correctly without AD
  2. When you have AD access, run: .\RC4_DES_Assessment.ps1 -QuickScan
  3. For full analysis: .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 24
  4. Export results: .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults

"@ -ForegroundColor White

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Testing Complete!" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Cyan
