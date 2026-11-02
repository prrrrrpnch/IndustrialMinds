# LAPTOP 2 (Windows): PLC + packet capture.  Started by laptop2_win_plc.bat (double-click that).
# Opens two PowerShell windows: the PLC, and a tshark capture of port 5020.
# Addresses come from config\lab.env (via scripts\run.ps1); nothing is hard-coded here.
param([ValidateSet('main', 'plc', 'capture')][string]$Mode = 'main')

$CaptureIface = '4'     # the adapter number from `tshark -D` for your Wi-Fi/Ethernet; change it here if it differs
$Tshark = 'C:\Program Files\Wireshark\tshark.exe'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

switch ($Mode) {
    'plc' {
        $Host.UI.RawUI.WindowTitle = 'PLC (Laptop 2)'
        . (Join-Path $root '.venv\Scripts\Activate.ps1')
        & (Join-Path $root 'scripts\run.ps1') plc
    }
    'capture' {
        $Host.UI.RawUI.WindowTitle = 'PLC-side capture (port 5020)'
        if (-not (Test-Path $Tshark)) { Write-Host "tshark not found at $Tshark" -ForegroundColor Red; return }
        & $Tshark -i $CaptureIface -f 'tcp port 5020' -o mbtcp.tcp.port:5020 -Y mbtcp
    }
    default {
        if (-not (Test-Path (Join-Path $root '.venv\Scripts\Activate.ps1'))) {
            Write-Host "No .venv found in $root - run the one-time setup first." -ForegroundColor Red; return
        }
        Write-Host 'Starting LAPTOP 2 (PLC + capture)...'
        foreach ($m in 'plc', 'capture') {
            Start-Process powershell -ArgumentList '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Mode', $m
            Start-Sleep -Seconds 2
        }
        Write-Host ''
        Write-Host 'Two windows are open: PLC and capture. Leave them open.'
        Write-Host 'The PLC window should say it is listening on port 5020. Then start Laptop 1.'
        Write-Host 'To stop: close the two windows (or Ctrl+C in each).'
    }
}
