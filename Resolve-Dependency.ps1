<#
    .SYNOPSIS
        Resolve build dependencies from RequiredModules.psd1.

    .DESCRIPTION
        Installs all modules listed in RequiredModules.psd1 to the output/RequiredModules
        directory for use during the build process.
#>
[CmdletBinding()]
param ()

$requiredModulesPath = Join-Path -Path $PSScriptRoot -ChildPath 'RequiredModules.psd1'
$configPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resolve-Dependency.psd1'

if (-not (Test-Path -Path $requiredModulesPath))
{
    Write-Error "RequiredModules.psd1 not found at: $requiredModulesPath"
    return
}

$requiredModules = Import-PowerShellDataFile -Path $requiredModulesPath

$config = @{
    Gallery         = 'PSGallery'
    AllowPrerelease = $false
}

if (Test-Path -Path $configPath)
{
    $fileConfig = Import-PowerShellDataFile -Path $configPath
    foreach ($key in $fileConfig.Keys)
    {
        $config[$key] = $fileConfig[$key]
    }
}

$outputPath = Join-Path -Path $PSScriptRoot -ChildPath 'output' 'RequiredModules'
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

Write-Host 'Resolving dependencies...' -ForegroundColor Cyan

foreach ($moduleName in $requiredModules.Keys)
{
    $moduleVersion = $requiredModules[$moduleName]

    $installed = Get-Module -Name $moduleName -ListAvailable |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if ($installed)
    {
        Write-Host "  [OK] $moduleName v$($installed.Version)" -ForegroundColor Green
    }
    else
    {
        Write-Host "  [Installing] $moduleName..." -ForegroundColor Yellow

        $installParams = @{
            Name        = $moduleName
            Repository  = $config.Gallery
            Force       = $true
            Scope       = 'CurrentUser'
        }

        if ($moduleVersion -ne 'latest')
        {
            $installParams['RequiredVersion'] = $moduleVersion
        }

        try
        {
            Install-Module @installParams -ErrorAction Stop
            Write-Host "  [OK] $moduleName installed." -ForegroundColor Green
        }
        catch
        {
            Write-Warning "  [FAILED] $moduleName: $_"
        }
    }
}

Write-Host "`nDependency resolution complete." -ForegroundColor Cyan
