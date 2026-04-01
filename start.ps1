param(
    [ValidateSet(8010)]
    [int]$BackendPort = 8010,
    [ValidateSet(5500)]
    [int]$FrontendPort = 5500,
    [switch]$BackendOnly,
    [switch]$FrontendOnly,
    [switch]$ForceRestart
)

$ErrorActionPreference = "Stop"

if ($BackendOnly -and $FrontendOnly) {
    throw "Não é possível usar -BackendOnly e -FrontendOnly ao mesmo tempo."
}

$startBackend = -not $FrontendOnly
$startFrontend = -not $BackendOnly

function Get-ListeningPids {
    param([int]$Port)

    $hits = netstat -ano | Select-String "LISTENING" | Where-Object {
        $_.ToString() -match (":" + $Port + "\s")
    }

    $pids = @()
    foreach ($line in $hits) {
        $text = $line.ToString()
        if ($text -match "\s+(\d+)\s*$") {
            $pids += [int]$matches[1]
        }
    }

    return @($pids | Select-Object -Unique)
}

function Test-PortListening {
    param([int]$Port)
    return ((Get-ListeningPids -Port $Port).Count -gt 0)
}

function Test-Url200 {
    param(
        [string]$Url,
        [int]$TimeoutSec = 6
    )

    try {
        $status = (Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec $TimeoutSec).StatusCode
        return ($status -ge 200 -and $status -lt 300)
    } catch {
        return $false
    }
}

function Resolve-Python {
    param([string]$BackendDir)

    $venvPy = Join-Path $BackendDir ".venv\Scripts\python.exe"
    if (Test-Path $venvPy) {
        return $venvPy
    }

    $globalPy = "C:\Users\mscaff\AppData\Local\Programs\Python\Python312\python.exe"
    if (Test-Path $globalPy) {
        return $globalPy
    }

    throw "Python não encontrado. Instale Python ou crie .venv no backend."
}

function Stop-ProcessSafe {
    param(
        [int]$ProcessId,
        [string]$Label
    )

    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($proc) {
        try {
            Stop-Process -Id $ProcessId -Force
            Write-Host "${Label}: processo $ProcessId finalizado."
        } catch {
            Write-Host "${Label}: falha ao encerrar $ProcessId ($($_.Exception.Message))."
        }
    }
}

function Stop-ByPidFile {
    param(
        [string]$Label,
        [string]$PidFile
    )

    if (!(Test-Path $PidFile)) {
        return
    }

    $raw = (Get-Content -Path $PidFile -Raw).Trim()
    if ($raw -and $raw -match "^\d+$") {
        Stop-ProcessSafe -ProcessId ([int]$raw) -Label $Label
    }

    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

function Stop-ByPort {
    param(
        [string]$Label,
        [int]$Port
    )

    foreach ($pidValue in (Get-ListeningPids -Port $Port)) {
        Stop-ProcessSafe -ProcessId $pidValue -Label "$Label(port $Port)"
    }
}

function Read-PidFile {
    param([string]$PidFile)

    if (!(Test-Path $PidFile)) {
        return $null
    }

    $raw = (Get-Content -Path $PidFile -Raw).Trim()
    if ($raw -match "^\d+$") {
        return [int]$raw
    }
    return $null
}

$root = $PSScriptRoot
$backendDir = Join-Path $root "backend"
$frontendDir = Join-Path $root "frontend"
$runtimeDir = Join-Path $root ".runtime"

New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null

$backendPidFile = Join-Path $runtimeDir "backend.pid"
$frontendPidFile = Join-Path $runtimeDir "frontend.pid"
$backendOut = Join-Path $runtimeDir ("backend_" + $BackendPort + ".out.log")
$backendErr = Join-Path $runtimeDir ("backend_" + $BackendPort + ".err.log")
$frontendOut = Join-Path $runtimeDir ("frontend_" + $FrontendPort + ".out.log")
$frontendErr = Join-Path $runtimeDir ("frontend_" + $FrontendPort + ".err.log")

if ($ForceRestart) {
    if ($startBackend) {
        Stop-ByPidFile -Label "Backend" -PidFile $backendPidFile
        Stop-ByPort -Label "Backend" -Port $BackendPort
    }
    if ($startFrontend) {
        Stop-ByPidFile -Label "Frontend" -PidFile $frontendPidFile
        Stop-ByPort -Label "Frontend" -Port $FrontendPort
    }
}

$pythonExe = Resolve-Python -BackendDir $backendDir

foreach ($f in @($backendOut, $backendErr, $frontendOut, $frontendErr)) {
    if (Test-Path $f) {
        try {
            Remove-Item $f -Force
        } catch {
            Write-Host "Aviso: não foi possível remover log em uso: $f"
        }
    }
}

$backendStatus = "skip"
$frontendStatus = "skip"
$backendPid = ""
$frontendPid = ""

if ($startBackend) {
    $knownBackendPid = Read-PidFile -PidFile $backendPidFile
    $backendPortPids = @(Get-ListeningPids -Port $BackendPort)

    if (Test-PortListening -Port $BackendPort) {
        $managedBackend = $knownBackendPid -and ($backendPortPids -contains $knownBackendPid)
        if ($managedBackend -and (Test-Url200 -Url "http://127.0.0.1:$BackendPort/api/health" -TimeoutSec 4)) {
            $backendStatus = "already_running"
            $backendPid = $knownBackendPid
            if ($backendPid) {
                $backendPid | Set-Content -Path $backendPidFile -Encoding ascii
            }
        } else {
            $pidListText = if ($backendPortPids.Count) { ($backendPortPids -join ", ") } else { "desconhecido" }
            throw "Porta $BackendPort já está em uso por processo externo (PID: $pidListText). Pare esse processo ou inicie com outra porta."
        }
    } else {
        $backendProc = Start-Process `
            -FilePath $pythonExe `
            -ArgumentList @("-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "$BackendPort") `
            -WorkingDirectory $backendDir `
            -RedirectStandardOutput $backendOut `
            -RedirectStandardError $backendErr `
            -PassThru

        $backendProc.Id | Set-Content -Path $backendPidFile -Encoding ascii
        $backendPid = $backendProc.Id

        $healthy = $false
        for ($i = 0; $i -lt 18; $i++) {
            if (Test-Url200 -Url "http://127.0.0.1:$BackendPort/api/health" -TimeoutSec 4) {
                $healthy = $true
                break
            }
            Start-Sleep -Milliseconds 750
        }

        if (!$healthy) {
            throw "Backend não subiu corretamente em $BackendPort. Verifique logs: $backendErr"
        }
        $backendStatus = "started"
    }
}

if ($startFrontend) {
    $knownFrontendPid = Read-PidFile -PidFile $frontendPidFile
    $frontendPortPids = @(Get-ListeningPids -Port $FrontendPort)

    if (Test-PortListening -Port $FrontendPort) {
        $managedFrontend = $knownFrontendPid -and ($frontendPortPids -contains $knownFrontendPid)
        if ($managedFrontend -and (Test-Url200 -Url "http://127.0.0.1:$FrontendPort/index.html" -TimeoutSec 4)) {
            $frontendStatus = "already_running"
            $frontendPid = $knownFrontendPid
            if ($frontendPid) {
                $frontendPid | Set-Content -Path $frontendPidFile -Encoding ascii
            }
        } else {
            $pidListText = if ($frontendPortPids.Count) { ($frontendPortPids -join ", ") } else { "desconhecido" }
            throw "Porta $FrontendPort já está em uso por processo externo (PID: $pidListText). Pare esse processo ou inicie com outra porta."
        }
    } else {
        $frontendProc = Start-Process `
            -FilePath $pythonExe `
            -ArgumentList @("-m", "http.server", "$FrontendPort", "--bind", "127.0.0.1") `
            -WorkingDirectory $frontendDir `
            -RedirectStandardOutput $frontendOut `
            -RedirectStandardError $frontendErr `
            -PassThru

        $frontendProc.Id | Set-Content -Path $frontendPidFile -Encoding ascii
        $frontendPid = $frontendProc.Id

        $healthy = $false
        for ($i = 0; $i -lt 10; $i++) {
            if (Test-Url200 -Url "http://127.0.0.1:$FrontendPort/index.html" -TimeoutSec 4) {
                $healthy = $true
                break
            }
            Start-Sleep -Milliseconds 500
        }

        if (!$healthy) {
            throw "Frontend não subiu corretamente em $FrontendPort. Verifique logs: $frontendErr"
        }
        $frontendStatus = "started"
    }
}

Write-Host "Backend status: $backendStatus"
if ($startBackend) {
    $backendHealth = if (Test-Url200 -Url "http://127.0.0.1:$BackendPort/api/health" -TimeoutSec 4) { "200" } else { "ERR" }
    Write-Host "Backend PID: $backendPid"
    Write-Host "Backend URL: http://127.0.0.1:$BackendPort"
    Write-Host "Health check backend: $backendHealth"
}

Write-Host "Frontend status: $frontendStatus"
if ($startFrontend) {
    $frontendHealth = if (Test-Url200 -Url "http://127.0.0.1:$FrontendPort/index.html" -TimeoutSec 4) { "200" } else { "ERR" }
    Write-Host "Frontend PID: $frontendPid"
    Write-Host "Frontend URL: http://127.0.0.1:$FrontendPort/index.html"
    Write-Host "Health check frontend: $frontendHealth"
}
