# Copilot Instructions for RC4-ADAssessment

## CRITICAL: Build & Test Execution Safety

**NEVER** run `./build.ps1`, `Invoke-Pester`, `Invoke-Build`, or any long-running
PowerShell command directly in the VS Code integrated terminal. This includes wrapping
in `pwsh -Command "..."` — the terminal still blocks synchronously and freezes VS Code.

**NEVER** use the `runTests` tool for this project.

**ALWAYS** use `Start-Process` (fully detached) with log polling:

```powershell
$logPath = "$env:TEMP\sampler_build.log"
Remove-Item $logPath -ErrorAction SilentlyContinue
Start-Process -FilePath pwsh -ArgumentList @(
    '-NoProfile', '-NonInteractive', '-Command',
    "Set-Location '$PWD'; .\build.ps1 -Tasks test *>&1 | Out-File -FilePath '$logPath' -Encoding utf8"
) -WindowStyle Hidden -PassThru

for ($i = 0; $i -lt 120; $i++) {
    Start-Sleep 3
    if (Test-Path $logPath) {
        $c = Get-Content $logPath -Raw -ErrorAction SilentlyContinue
        if ($c -match 'Build (FAILED|succeeded)') {
            Get-Content $logPath -Tail 30
            break
        }
    }
    if ($i % 10 -eq 0) { Write-Host "Waiting... ($($i*3)s)" }
}
```

### Log Path: MUST use `$env:TEMP`

Never put the log file inside `output/`. Sampler's Clean task deletes everything in
`output/` at the start of a build, which locks the log file and fails the build.

## Project Overview

This is a Sampler-based PowerShell module (RC4-ADAssessment) that assesses Active Directory
environments for RC4 encryption usage. It uses ModuleBuilder to compile source files
from `source/Public/` and `source/Private/` into a single `.psm1`.

Key conventions:
- Build system: Sampler + InvokeBuild + ModuleBuilder
- Test framework: Pester 5
- Module prefix file: `source/prefix.ps1` (injected at top of built module)
- Build config: `build.yaml`
- Dependencies already resolved in `output/RequiredModules/` — skip `-ResolveDependency`

## Available CLI Tools

- **GitHub CLI (`gh`)**: Always available on this machine. Use `gh` for creating PRs,
  managing issues, checking workflow status, etc. No need to search for MCP tools or
  alternative approaches — just call `gh` directly via the terminal.
