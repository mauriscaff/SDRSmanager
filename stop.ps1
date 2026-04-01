param(
    [ValidateSet(8010)]
    [int]$BackendPort = 8010,
    [ValidateSet(5500)]
    [int]$FrontendPort = 5500
)

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$runtimeDir = Join-Path $root ".runtime"
$backendPidFile = Join-Path $runtimeDir "backend.pid"
$frontendPidFile = Join-Path $runtimeDir "frontend.pid"

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

function Stop-ProcessSafe {
    param(
        [string]$Label,
        [int]$ProcessId
    )

    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($proc) {
        try {
            Stop-Process -Id $ProcessId -Force
            Write-Host "${Label}: processo $ProcessId finalizado."
        } catch {
            Write-Host "${Label}: não foi possível encerrar $ProcessId ($($_.Exception.Message))."
        }
    } else {
        Write-Host "${Label}: processo $ProcessId já não estava em execução."
    }
}

function Stop-FromPidFile {
    param(
        [string]$Label,
        [string]$PidFile
    )

    if (!(Test-Path $PidFile)) {
        Write-Host "${Label}: PID file não encontrado."
        return
    }

    $raw = (Get-Content -Path $PidFile -Raw).Trim()
    if (-not $raw) {
        Write-Host "${Label}: PID vazio."
        Remove-Item $PidFile -Force
        return
    }

    if ($raw -match "^\d+$") {
        Stop-ProcessSafe -Label $Label -ProcessId ([int]$raw)
    } else {
        Write-Host "${Label}: PID inválido no arquivo."
    }

    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

function Stop-ByPort {
    param(
        [string]$Label,
        [int]$Port
    )

    $pids = Get-ListeningPids -Port $Port
    if (!$pids.Count) {
        Write-Host "${Label}: nenhuma escuta ativa na porta $Port."
        return
    }

    foreach ($pidValue in $pids) {
        Stop-ProcessSafe -Label "${Label}(porta $Port)" -ProcessId $pidValue
    }
}

Stop-FromPidFile -Label "Backend" -PidFile $backendPidFile
Stop-FromPidFile -Label "Frontend" -PidFile $frontendPidFile

Stop-ByPort -Label "Backend" -Port $BackendPort
Stop-ByPort -Label "Frontend" -Port $FrontendPort
