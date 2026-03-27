<#
    .SYNOPSIS
        Bootstrap script for Sampler-based builds.

    .DESCRIPTION
        This script is the entry point for the build pipeline. It resolves dependencies
        and invokes the build tasks defined in build.yaml.

    .PARAMETER ResolveDependency
        Resolve build dependencies before running tasks.

    .PARAMETER Tasks
        The build tasks to run. Default is '.', which runs the default workflow.

    .PARAMETER CodeCoverageThreshold
        Override the code coverage threshold from build.yaml.

    .PARAMETER BuildConfig
        The build configuration file. Default is 'build.yaml'.
#>
[CmdletBinding()]
param
(
    [Parameter(Position = 0)]
    [string[]]
    $Tasks = '.',

    [Parameter()]
    [switch]
    $ResolveDependency,

    [Parameter()]
    [string]
    $BuildConfig = 'build.yaml',

    [Parameter()]
    [int]
    $CodeCoverageThreshold
)

# Bootstrap: Install and import required modules
if ($ResolveDependency)
{
    Write-Host 'Resolving build dependencies...' -ForegroundColor Cyan

    $resolveDependencyScript = Join-Path -Path $PSScriptRoot -ChildPath 'Resolve-Dependency.ps1'

    if (Test-Path -Path $resolveDependencyScript)
    {
        & $resolveDependencyScript
    }
    else
    {
        Write-Host 'Resolve-Dependency.ps1 not found. Installing required modules directly...' -ForegroundColor Yellow

        $requiredModulesPath = Join-Path -Path $PSScriptRoot -ChildPath 'RequiredModules.psd1'
        $requiredModules = Import-PowerShellDataFile -Path $requiredModulesPath

        $outputModulesPath = Join-Path -Path $PSScriptRoot -ChildPath 'output' 'RequiredModules'
        New-Item -ItemType Directory -Path $outputModulesPath -Force | Out-Null

        foreach ($moduleName in $requiredModules.Keys)
        {
            $installedModule = Get-Module -Name $moduleName -ListAvailable |
                Sort-Object Version -Descending |
                Select-Object -First 1

            if (-not $installedModule)
            {
                Write-Host "  Installing $moduleName..." -ForegroundColor DarkGray
                $installParams = @{
                    Name            = $moduleName
                    Repository      = 'PSGallery'
                    Force           = $true
                    AllowClobber    = $true
                    Scope           = 'CurrentUser'
                    ErrorAction     = 'Stop'
                }

                try
                {
                    Install-Module @installParams
                }
                catch
                {
                    Write-Warning "Failed to install $moduleName : $_"
                }
            }
            else
            {
                Write-Host "  $moduleName v$($installedModule.Version) already installed." -ForegroundColor DarkGray
            }
        }
    }
}

# Import InvokeBuild
$invokeBuildModule = Get-Module -Name InvokeBuild -ListAvailable |
    Sort-Object Version -Descending |
    Select-Object -First 1

if (-not $invokeBuildModule)
{
    Write-Error 'InvokeBuild module not found. Run with -ResolveDependency first.'
    return
}

Import-Module -Name InvokeBuild -Force

# Import Sampler
$samplerModule = Get-Module -Name Sampler -ListAvailable |
    Sort-Object Version -Descending |
    Select-Object -First 1

if ($samplerModule)
{
    Import-Module -Name Sampler -Force
}
else
{
    Write-Warning 'Sampler module not found. Some build tasks may not be available.'
}

# Set up build variables
$buildConfigPath = Join-Path -Path $PSScriptRoot -ChildPath $BuildConfig

if (-not (Test-Path -Path $buildConfigPath))
{
    Write-Error "Build configuration file not found: $buildConfigPath"
    return
}

# Read build configuration
$buildYaml = Get-Content -Path $buildConfigPath -Raw

if (Get-Command -Name ConvertFrom-Yaml -ErrorAction SilentlyContinue)
{
    $buildInfo = ConvertFrom-Yaml -Yaml $buildYaml
}
else
{
    # Fallback: Use PowerShell-YAML if available
    Import-Module -Name powershell-yaml -ErrorAction SilentlyContinue
    if (Get-Command -Name ConvertFrom-Yaml -ErrorAction SilentlyContinue)
    {
        $buildInfo = ConvertFrom-Yaml -Yaml $buildYaml
    }
    else
    {
        Write-Error 'Cannot parse YAML. Install powershell-yaml module.'
        return
    }
}

# Invoke the build
try
{
    Invoke-Build -Task $Tasks -File (Join-Path -Path $samplerModule.ModuleBase -ChildPath 'Sampler.build.ps1') -BuildInfo $buildInfo -ErrorAction Stop
}
catch
{
    Write-Error "Build failed: $_"
    exit 1
}
