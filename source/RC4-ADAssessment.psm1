# RC4-ADAssessment Module
# This file is populated by ModuleBuilder during the build process.
# For development, it dot-sources all public and private functions.

$script:Version = (Import-PowerShellDataFile -Path "$PSScriptRoot\RC4-ADAssessment.psd1").ModuleVersion
$script:AssessmentTimestamp = Get-Date

$privatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Private'
$publicPath = Join-Path -Path $PSScriptRoot -ChildPath 'Public'

# Dot-source private functions
if (Test-Path -Path $privatePath) {
    $privateFiles = Get-ChildItem -Path $privatePath -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $privateFiles) {
        try {
            . $file.FullName
        }
        catch {
            Write-Error -Message "Failed to import private function $($file.BaseName): $_"
        }
    }
}

# Dot-source public functions
if (Test-Path -Path $publicPath) {
    $publicFiles = Get-ChildItem -Path $publicPath -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $publicFiles) {
        try {
            . $file.FullName
        }
        catch {
            Write-Error -Message "Failed to import public function $($file.BaseName): $_"
        }
    }
}
