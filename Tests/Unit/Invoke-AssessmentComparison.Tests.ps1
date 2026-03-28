Describe 'Invoke-AssessmentComparison' {
    BeforeAll {
        $script:tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "PesterCompare_$(Get-Random)"
        New-Item -Path $script:tempDir -ItemType Directory -Force | Out-Null

        $baseline = @{
            Domain = 'contoso.com'; OverallStatus = 'WARNING'; Version = '4.0.0'
            AssessmentDate = '2026-01-01T10:00:00'
            DomainControllers = @{ TotalDCs = 2; AESConfigured = 1; RC4Configured = 1; DESConfigured = 0; NotConfigured = 0 }
            Trusts = @{ TotalTrusts = 1; RC4Risk = 1; DESRisk = 0 }
            Accounts = @{ KRBTGT = @{ Status = 'OK'; PasswordAgeDays = 90 }; TotalRC4OnlySvc = 2; TotalRC4OnlyMSA = 0; TotalDESFlag = 0; TotalStaleSvc = 0; TotalMissingAES = 1; TotalRC4Exception = 0; TotalDESEnabled = 0 }
            EventLogs = @{ TotalEventsAnalyzed = 500; RC4Tickets = 50; DESTickets = 5; AESTickets = 445 }
            KdcRegistry = @{ DefaultDomainSupportedEncTypes = @{ Value = $null; Status = 'Not Set' }; RC4DefaultDisablementPhase = @{ Value = $null; Status = 'Not Set' } }
            KdcSvcEvents = @{ TotalEvents = 0; Status = 'OK' }
        }
        $current = @{
            Domain = 'contoso.com'; OverallStatus = 'OK'; Version = '4.0.0'
            AssessmentDate = '2026-03-01T10:00:00'
            DomainControllers = @{ TotalDCs = 2; AESConfigured = 2; RC4Configured = 0; DESConfigured = 0; NotConfigured = 0 }
            Trusts = @{ TotalTrusts = 1; RC4Risk = 0; DESRisk = 0 }
            Accounts = @{ KRBTGT = @{ Status = 'OK'; PasswordAgeDays = 30 }; TotalRC4OnlySvc = 0; TotalRC4OnlyMSA = 0; TotalDESFlag = 0; TotalStaleSvc = 0; TotalMissingAES = 0; TotalRC4Exception = 0; TotalDESEnabled = 0 }
            EventLogs = @{ TotalEventsAnalyzed = 600; RC4Tickets = 0; DESTickets = 0; AESTickets = 600 }
            KdcRegistry = @{ DefaultDomainSupportedEncTypes = @{ Value = 24; Status = 'OK' }; RC4DefaultDisablementPhase = @{ Value = 1; Status = 'OK' } }
            KdcSvcEvents = @{ TotalEvents = 0; Status = 'OK' }
        }

        $script:baselineFile = Join-Path $script:tempDir 'baseline.json'
        $script:currentFile = Join-Path $script:tempDir 'current.json'
        $baseline | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:baselineFile -Encoding UTF8
        $current | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:currentFile -Encoding UTF8
    }

    AfterAll {
        Remove-Item -Path $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        Mock -ModuleName 'RC4ADCheck' Write-Host {}
    }

    It 'Does not throw with valid JSON files' {
        { Invoke-AssessmentComparison -BaselineFile $script:baselineFile -CurrentFile $script:currentFile } | Should -Not -Throw
    }

    It 'Throws with a non-existent baseline file' {
        { Invoke-AssessmentComparison -BaselineFile 'C:\nonexistent.json' -CurrentFile $script:currentFile } | Should -Throw
    }
}
