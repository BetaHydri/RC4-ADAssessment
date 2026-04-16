# Resolve module version dynamically from the manifest that lives next to this .psm1.
# Sampler/ModuleBuilder stamps the real version into the built .psd1, so this always
# reflects the installed release (e.g. 4.11.0) rather than the source placeholder 0.0.1.
$script:Version = (Import-PowerShellDataFile -Path "$PSScriptRoot\RC4-ADAssessment.psd1").ModuleVersion
$script:AssessmentTimestamp = Get-Date
