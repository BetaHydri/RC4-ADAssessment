function Invoke-DomainAssessment {
    param(
        [string]$DomainName,
        [bool]$AnalyzeLogs,
        [int]$Hours,
        [bool]$Export,
        [bool]$Guidance
    )
    
    Write-Host "`n$("=" * 80)" -ForegroundColor Yellow
    Write-Host "Assessing Domain: $DomainName" -ForegroundColor Yellow
    Write-Host $("=" * 80) -ForegroundColor Yellow
    
    # Try to discover a specific DC in this domain for better connectivity
    $serverParam = $null
    try {
        Write-Host "  Discovering Domain Controller for $DomainName..." -ForegroundColor Gray
        $dc = Get-ADDomainController -DomainName $DomainName -Discover -ErrorAction Stop
        # Extract hostname as a simple string (handle arrays, collections, and objects)
        if ($dc.HostName -is [array]) {
            $serverParam = [string]$dc.HostName[0]
        }
        elseif ($dc.HostName.Value) {
            # Handle ADPropertyValueCollection
            $serverParam = [string]$dc.HostName.Value
        }
        else {
            # Direct property access
            $serverParam = [string]$dc.HostName
        }
        Write-Host "  Using DC: $serverParam" -ForegroundColor Green
    }
    catch {
        Write-Host "  Could not discover DC, using domain name directly" -ForegroundColor Yellow
        Write-Host "  Warning: This may fail for child domains if not directly reachable" -ForegroundColor Yellow
    }
    
    # Build command parameters
    $params = @{}
    
    if ($serverParam) {
        # Use -Server with the discovered DC hostname
        $params['Server'] = $serverParam
    }
    else {
        # Fall back to -Domain
        $params['Domain'] = $DomainName
    }
    
    if ($AnalyzeLogs) {
        $params['AnalyzeEventLogs'] = $true
        $params['EventLogHours'] = $Hours
    }
    
    if ($Export) {
        $params['ExportResults'] = $true
    }
    
    if ($Guidance) {
        $params['IncludeGuidance'] = $true
    }
    
    try {
        # Run assessment and capture returned results object
        $assessmentResults = Invoke-RC4Assessment @params
        
        # Parse results (if exported)
        if ($Export) {
            $domainSafe = $DomainName -replace '\.', '_'
            $timestamp = Get-Date -Format "yyyyMMdd"
            $jsonPattern = "DES_RC4_Assessment_${domainSafe}_${timestamp}*.json"
            
            # Look in Exports folder first, then fallback to script root
            $exportFolder = Join-Path -Path $PSScriptRoot -ChildPath "Exports"
            $resultFile = Get-ChildItem -Path $exportFolder -Filter $jsonPattern -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 1
            
            if (-not $resultFile) {
                # Fallback to script root for backwards compatibility
                $resultFile = Get-ChildItem -Path $PSScriptRoot -Filter $jsonPattern -ErrorAction SilentlyContinue | 
                Sort-Object LastWriteTime -Descending | 
                Select-Object -First 1
            }
            
            if ($resultFile) {
                $result = Get-Content $resultFile.FullName | ConvertFrom-Json
                return @{
                    Domain = $DomainName
                    Status = $result.OverallStatus
                    Data   = $result
                }
            }
        }
        
        # Return results from the script execution
        if ($assessmentResults) {
            return @{
                Domain = $DomainName
                Status = $assessmentResults.OverallStatus
                Data   = $assessmentResults
            }
        }
        
        return @{
            Domain = $DomainName
            Status = "Completed"
            Data   = $null
        }
    }
    catch {
        Write-Warning "Failed to assess domain $DomainName : $($_.Exception.Message)"
        return @{
            Domain = $DomainName
            Status = "Failed"
            Error  = $_.Exception.Message
            Data   = $null
        }
    }
}

