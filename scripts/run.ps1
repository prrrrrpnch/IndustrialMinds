<#
  IndustrialMind launcher (Windows PowerShell) - one command per role.

    .\scripts\run.ps1 plc                      # Windows A
    .\scripts\run.ps1 attacker hmac-tamper     # Windows B (extra args pass through)
    .\scripts\run.ps1 middleware               # (if a Windows laptop were the middleware)
    .\scripts\run.ps1 check attacker           # preflight for this role

  Reads config\lab.env (copy it from config\lab.env.example first). Every
  address and the shared secret come from there; nothing is hard-coded.
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('plc', 'dashboard', 'middleware', 'scada', 'attacker', 'check')]
    [string]$Role,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

# --- read config\lab.env into a hashtable ----------------------------------
$cfg = @{}
$envFile = Join-Path $Root 'config\lab.env'
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
            $k, $v = $line -split '=', 2
            $v = ($v -split '#', 2)[0].Trim()   # strip inline comments
            $cfg[$k.Trim()] = $v
        }
    }
}

function Get-Cfg([string]$key, [string]$fallback) {
    if ($cfg.ContainsKey($key) -and $cfg[$key]) { return $cfg[$key] } else { return $fallback }
}

$MW_IP       = Get-Cfg 'MW_IP'       '127.0.0.1'
$PLC_IP      = Get-Cfg 'PLC_IP'      '127.0.0.1'
$SCADA_IP    = Get-Cfg 'SCADA_IP'    '127.0.0.1'
$ATTACKER_IP = Get-Cfg 'ATTACKER_IP' '127.0.0.1'
$DASH_BIND   = Get-Cfg 'DASHBOARD_BIND_HOST' '127.0.0.1'
$SECRET      = Get-Cfg 'HMAC_SECRET' ''

$py = 'python'

function Set-Secret {
    if (-not $SECRET) {
        Write-Warning "HMAC_SECRET is not set in config\lab.env. SCADA, middleware and attacker must share one secret, or every command is rejected as HMAC_INVALID. Generate one with: python -c `"import secrets; print(secrets.token_hex(24))`""
    }
    else {
        $env:IM_HMAC_SECRET = $SECRET
    }
}

switch ($Role) {
    'plc' {
        & $py -m plc.plc @Rest
    }
    'dashboard' {
        $env:IM_DASHBOARD_BIND_HOST = $DASH_BIND
        & $py dashboard/app.py @Rest
    }
    'middleware' {
        $env:IM_PLC_HOST = $PLC_IP
        $env:IM_TRUSTED_SOURCES = "$SCADA_IP,$ATTACKER_IP"
        $env:IM_HOST_LABELS = "$SCADA_IP=SCADA operator,$ATTACKER_IP=Attacker laptop"
        # auto-quarantine: ON for a multi-laptop run, switched OFF by itself when every address is loopback (one-laptop demo)
        if (-not $env:IM_QUARANTINE) { $env:IM_QUARANTINE = "auto" }
        Set-Secret
        & $py -m middleware.middleware_server @Rest
    }
    'scada' {
        $env:IM_MIDDLEWARE_HOST = $MW_IP
        Set-Secret
        & $py -m scada.scada @Rest
    }
    'attacker' {
        $env:IM_MIDDLEWARE_HOST = $MW_IP
        $env:IM_PLC_HOST = $PLC_IP
        Set-Secret
        & $py -m attacker.attacker @Rest
    }
    'check' {
        $sub = if ($Rest.Count -ge 1) { $Rest[0] } else { '' }
        $env:IM_PLC_HOST = $PLC_IP
        $env:IM_MIDDLEWARE_HOST = $MW_IP
        $env:IM_TRUSTED_SOURCES = "$SCADA_IP,$ATTACKER_IP"
        if ($SECRET) { $env:IM_HMAC_SECRET = $SECRET }
        & $py -m tools.check_topology --role $sub --multi
    }
}
