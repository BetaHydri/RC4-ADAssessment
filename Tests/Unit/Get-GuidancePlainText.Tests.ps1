InModuleScope 'RC4ADCheck' {
Describe 'Get-GuidancePlainText' {
    It 'Returns a non-empty string' {
        $result = Get-GuidancePlainText -Domain 'contoso.com' -AssessmentDate '2026-03-27' -Version '4.0.0'
        $result | Should -Not -BeNullOrEmpty
    }

    It 'Includes the domain name in the output' {
        $result = Get-GuidancePlainText -Domain 'contoso.com' -AssessmentDate '2026-03-27' -Version '4.0.0'
        $result | Should -Match 'contoso\.com'
    }

    It 'Includes the assessment date in the output' {
        $result = Get-GuidancePlainText -Domain 'contoso.com' -AssessmentDate '2026-03-27' -Version '4.0.0'
        $result | Should -Match '2026-03-27'
    }

    It 'Includes the version in the output' {
        $result = Get-GuidancePlainText -Domain 'contoso.com' -AssessmentDate '2026-03-27' -Version '4.0.0'
        $result | Should -Match '4\.0\.0'
    }

    It 'Includes event log monitoring guidance' {
        $result = Get-GuidancePlainText -Domain 'contoso.com' -AssessmentDate '2026-03-27' -Version '4.0.0'
        $result | Should -Match 'Event Log'
    }
}
}
