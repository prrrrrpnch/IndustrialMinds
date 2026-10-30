# LAPTOP 4 (Windows): attacker menu.  Started by laptop4_win_attacker.bat (double-click that).
# Waits for the middleware, then lets you pick an attack by number. Addresses and the secret come from config\lab.env
# (via scripts\run.ps1); nothing is hard-coded here.
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$activate = Join-Path $root '.venv\Scripts\Activate.ps1'
if (-not (Test-Path $activate)) { Write-Host "No .venv found in $root - run the one-time setup first." -ForegroundColor Red; return }
. $activate
$run = Join-Path $root 'scripts\run.ps1'

# the middleware address from lab.env (loopback if blank)
$mw = '127.0.0.1'
$envFile = Join-Path $root 'config\lab.env'
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^\s*MW_IP\s*=\s*([^#\s]+)') { $mw = $Matches[1] }
    }
}

Write-Host "Waiting for the middleware at ${mw}:5021 (start Laptop 1 first; Ctrl+C to give up)..."
while ($true) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $iar = $c.BeginConnect($mw, 5021, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(2000) -and $c.Connected
        $c.Close()
        if ($ok) { break }
    } catch { }
    Start-Sleep -Seconds 2
}
Write-Host 'Middleware is reachable.' -ForegroundColor Green

$attacks = [ordered]@{
    '1'  = @('hmac-missing',       @('hmac-missing'))
    '2'  = @('hmac-tamper',        @('hmac-tamper'))
    '3'  = @('hmac-forged',        @('hmac-forged'))
    '4'  = @('replay',             @('replay'))
    '5'  = @('flood',              @('flood'))
    '6'  = @('impossible-command', @('impossible-command'))
    '7'  = @('sensor-write',       @('sensor-write'))
    '8'  = @('cross-register',     @('cross-register'))
    '9'  = @('random ramp',        @('random', '--type', 'ramp'))
    '10' = @('false-injection',    @('false-injection'))
}

function Show-Menu {
    Write-Host ''
    Write-Host '=== ATTACKER (Laptop 4) ===  wait ~2 min after the middleware starts so the model has warmed up' -ForegroundColor Cyan
    foreach ($k in $attacks.Keys) { Write-Host ("  {0,2}  {1}" -f $k, $attacks[$k][0]) }
    Write-Host '   A  run ALL of them, one after another'
    Write-Host '   Q  quit'
}

function Invoke-Attack($key) {
    Write-Host ''
    Write-Host ">>> attack: $($attacks[$key][0])" -ForegroundColor Yellow
    $atkArgs = $attacks[$key][1]
    & $run attacker @atkArgs
}

while ($true) {
    Show-Menu
    $choice = (Read-Host 'Choose').Trim().ToUpper()
    if ($choice -eq 'Q') { break }
    elseif ($choice -eq 'A') {
        foreach ($k in $attacks.Keys) { Invoke-Attack $k; Start-Sleep -Seconds 5 }
    }
    elseif ($attacks.Contains($choice)) { Invoke-Attack $choice }
    else { Write-Host 'Not a valid choice.' -ForegroundColor Red }
}
