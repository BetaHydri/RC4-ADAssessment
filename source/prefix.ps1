$script:Version = (Import-PowerShellDataFile -Path "$PSScriptRoot\RC4-ADAssessment.psd1").ModuleVersion
$script:AssessmentTimestamp = Get-Date
