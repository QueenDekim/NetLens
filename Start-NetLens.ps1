$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$pythonPath = Join-Path $PSScriptRoot 'third-party\python\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Bundled runtime missing. Restore third-party from the complete NetLens package.'
}
& $pythonPath -m netlens @args
