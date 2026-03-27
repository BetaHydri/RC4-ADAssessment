$script:Version = (Import-PowerShellDataFile -Path "$PSScriptRoot\RC4ADCheck.psd1").ModuleVersion
$script:AssessmentTimestamp = Get-Date
