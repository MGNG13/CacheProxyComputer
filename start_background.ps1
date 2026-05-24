$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exePath = Join-Path $scriptDir "proxy.exe"
if (-not (Test-Path -Path $exePath -PathType Leaf)) {
  throw "No se encontró proxy.exe en '$scriptDir'. Ejecuta .\build.ps1 primero."
}
$proc = Start-Process -FilePath $exePath -WorkingDirectory $scriptDir -WindowStyle Hidden -PassThru
Write-Output $proc.Id