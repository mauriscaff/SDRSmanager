param(
    [string]$ApiBase = "http://127.0.0.1:8010",
    [string]$ClusterId = "",
    [int]$TimeoutSec = 20,
    [string]$OutFile = ".runtime/qa_smoke_results.json"
)

$ErrorActionPreference = "Stop"

function Invoke-Api {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [object]$Body = $null
    )

    $uri = "$ApiBase$Path"
    $headers = @{ Accept = "application/json" }
    $status = 0
    $content = ""
    $json = $null
    $elapsedMs = 0.0

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if ($null -ne $Body) {
            $payload = $Body | ConvertTo-Json -Depth 10
            $resp = Invoke-WebRequest -Uri $uri -Method $Method -Headers $headers -ContentType "application/json" -Body $payload -TimeoutSec $TimeoutSec -UseBasicParsing
        } else {
            $resp = Invoke-WebRequest -Uri $uri -Method $Method -Headers $headers -TimeoutSec $TimeoutSec -UseBasicParsing
        }
        $status = [int]$resp.StatusCode
        $content = [string]$resp.Content
    } catch {
        if ($_.Exception.Response) {
            try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = 0 }
        }
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $content = [string]$_.ErrorDetails.Message
        } else {
            $content = [string]$_.Exception.Message
        }
    } finally {
        $sw.Stop()
        $elapsedMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
    }

    try {
        if ($content) {
            $json = $content | ConvertFrom-Json -ErrorAction Stop
        }
    } catch {
        $json = $null
    }

    return [pscustomobject]@{
        method = $Method
        path = $Path
        status = $status
        elapsed_ms = $elapsedMs
        body = $content
        json = $json
    }
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)]$Response,
        [Parameter(Mandatory = $true)][int[]]$ExpectedStatus,
        [scriptblock]$Validator = $null
    )

    $statusOk = $ExpectedStatus -contains [int]$Response.status
    $validatorOk = $true
    $note = ""

    if ($Validator) {
        try {
            $v = & $Validator $Response
            if ($v -is [hashtable]) {
                $validatorOk = [bool]$v.ok
                $note = [string]$v.note
            } else {
                $validatorOk = [bool]$v
            }
        } catch {
            $validatorOk = $false
            $note = "validator error: $($_.Exception.Message)"
        }
    }

    $pass = $statusOk -and $validatorOk
    if (-not $note) {
        $note = if ($pass) { "ok" } else { "unexpected status/body" }
    }

    return [pscustomobject]@{
        id = $Id
        severity = $Severity
        description = $Description
        method = $Response.method
        path = $Response.path
        status = [int]$Response.status
        expected = ($ExpectedStatus -join ",")
        elapsed_ms = $Response.elapsed_ms
        result = if ($pass) { "PASS" } else { "FAIL" }
        note = $note
    }
}

function Add-Skip {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    return [pscustomobject]@{
        id = $Id
        severity = $Severity
        description = $Description
        method = "-"
        path = "-"
        status = 0
        expected = "-"
        elapsed_ms = 0
        result = "SKIP"
        note = $Reason
    }
}

$results = @()

# Core health and root checks
$health = Invoke-Api -Method "GET" -Path "/api/health"
$results += Add-Check -Id "API-HEALTH-001" -Severity "P0" -Description "Health endpoint and read_only flag" -Response $health -ExpectedStatus @(200) -Validator {
    param($r)
    if ($null -eq $r.json) { return @{ ok = $false; note = "response is not JSON" } }
    $hasReadOnly = $null -ne $r.json.read_only
    $hasStatus = [string]$r.json.status -eq "ok"
    return @{ ok = ($hasReadOnly -and $hasStatus); note = if ($hasReadOnly -and $hasStatus) { "ok" } else { "missing status=ok or read_only" } }
}

$root = Invoke-Api -Method "GET" -Path "/"
$results += Add-Check -Id "API-ROOT-001" -Severity "P2" -Description "Root endpoint basic contract" -Response $root -ExpectedStatus @(200) -Validator {
    param($r)
    if ($null -eq $r.json) { return @{ ok = $false; note = "response is not JSON" } }
    $ok = [string]$r.json.docs -eq "/docs"
    return @{ ok = $ok; note = if ($ok) { "ok" } else { "docs field mismatch" } }
}

$readOnly = $true
if ($null -ne $health.json -and $null -ne $health.json.read_only) {
    $readOnly = [bool]$health.json.read_only
}

$clusters = Invoke-Api -Method "GET" -Path "/api/clusters"
$results += Add-Check -Id "CLUSTER-LIST-001" -Severity "P1" -Description "List clusters returns array" -Response $clusters -ExpectedStatus @(200) -Validator {
    param($r)
    if ($null -eq $r.json) { return @{ ok = $false; note = "response is not JSON" } }
    $ok = $r.json -is [System.Array]
    return @{ ok = $ok; note = if ($ok) { "ok" } else { "body is not array" } }
}

$targetClusterId = $ClusterId
if (-not $targetClusterId -and $clusters.status -eq 200 -and ($clusters.json -is [System.Array]) -and $clusters.json.Count -gt 0) {
    $targetClusterId = [string]$clusters.json[0].id
}

# Read-only guard checks (safe with dummy key; no apply/dismiss action should be performed in this phase)
$probeCluster = if ($targetClusterId) { $targetClusterId } else { "group-pod-readonly-probe" }
$probeKey = "qa-readonly-probe"

$applyResp = Invoke-Api -Method "POST" -Path "/api/clusters/$probeCluster/recs/$probeKey/apply"
$applyExpected = if ($readOnly) { @(403) } else { @(501) }
$results += Add-Check -Id "READONLY-APPLY-001" -Severity "P0" -Description "Apply endpoint behavior respects read-only mode" -Response $applyResp -ExpectedStatus $applyExpected

$dismissResp = Invoke-Api -Method "POST" -Path "/api/clusters/$probeCluster/recs/$probeKey/dismiss"
$dismissExpected = if ($readOnly) { @(403) } else { @(200) }
$results += Add-Check -Id "READONLY-DISMISS-001" -Severity "P0" -Description "Dismiss endpoint behavior respects read-only mode" -Response $dismissResp -ExpectedStatus $dismissExpected

# Analytics checks
$snapshot = Invoke-Api -Method "GET" -Path "/api/analytics/dashboard/snapshot"
$results += Add-Check -Id "AN-SNAPSHOT-001" -Severity "P0" -Description "Dashboard snapshot should return valid payload" -Response $snapshot -ExpectedStatus @(200) -Validator {
    param($r)
    if ($null -eq $r.json) { return @{ ok = $false; note = "response is not JSON" } }
    $hasGlobal = $null -ne $r.json.global
    return @{ ok = $hasGlobal; note = if ($hasGlobal) { "ok" } else { "missing global object" } }
}

$overview = Invoke-Api -Method "GET" -Path "/api/analytics/clusters/overview"
$results += Add-Check -Id "AN-OVERVIEW-001" -Severity "P1" -Description "Cluster overview endpoint contract" -Response $overview -ExpectedStatus @(200)

$insights = Invoke-Api -Method "GET" -Path "/api/analytics/clusters/insights"
$results += Add-Check -Id "AN-INSIGHTS-001" -Severity "P1" -Description "Cluster insights endpoint contract" -Response $insights -ExpectedStatus @(200)

$diagPath = if ($targetClusterId) { "/api/diagnostics/latency?cluster_id=$targetClusterId&max_datastores=2" } else { "/api/diagnostics/latency?max_datastores=2" }
$diag = Invoke-Api -Method "GET" -Path $diagPath
$results += Add-Check -Id "DIAG-LATENCY-001" -Severity "P2" -Description "Latency diagnostics endpoint availability" -Response $diag -ExpectedStatus @(200)

if ($targetClusterId) {
    $detail = Invoke-Api -Method "GET" -Path "/api/clusters/$targetClusterId"
    $results += Add-Check -Id "CLUSTER-DETAIL-001" -Severity "P1" -Description "Cluster detail contract fields" -Response $detail -ExpectedStatus @(200) -Validator {
        param($r)
        if ($null -eq $r.json) { return @{ ok = $false; note = "response is not JSON" } }
        $hasDatastores = $r.json.datastores -is [System.Array]
        if (-not $hasDatastores) { return @{ ok = $false; note = "missing datastores array" } }
        if ($r.json.datastores.Count -eq 0) { return @{ ok = $true; note = "empty datastores array" } }
        $first = $r.json.datastores[0]
        $needed = @("id", "name", "capacity_gb", "free_gb", "used_pct", "latency_ms")
        $missing = @()
        foreach ($k in $needed) {
            if ($null -eq $first.$k -and -not ($first.PSObject.Properties.Name -contains $k)) {
                $missing += $k
            }
        }
        if ($missing.Count -gt 0) { return @{ ok = $false; note = "missing fields: $($missing -join ', ')" } }
        return @{ ok = $true; note = "ok" }
    }

    $recs = Invoke-Api -Method "GET" -Path "/api/clusters/$targetClusterId/recs"
    $results += Add-Check -Id "RECS-CLUSTER-001" -Severity "P1" -Description "Cluster recommendations endpoint returns list" -Response $recs -ExpectedStatus @(200) -Validator {
        param($r)
        $ok = $r.json -is [System.Array]
        if (-not $ok) { return @{ ok = $false; note = "body is not array" } }
        if ($r.json.Count -eq 0) { return @{ ok = $true; note = "empty list" } }
        $first = $r.json[0]
        $needed = @("key", "type", "reason", "source_ds", "target_ds", "vm_name", "size_gb")
        $missing = @()
        foreach ($k in $needed) {
            if ($null -eq $first.$k -and -not ($first.PSObject.Properties.Name -contains $k)) {
                $missing += $k
            }
        }
        return @{ ok = ($missing.Count -eq 0); note = if ($missing.Count -eq 0) { "ok" } else { "missing fields: $($missing -join ', ')" } }
    }

    $candidates = Invoke-Api -Method "GET" -Path "/api/clusters/$targetClusterId/candidates?limit=10"
    $results += Add-Check -Id "CAND-CLUSTER-001" -Severity "P1" -Description "Heuristic candidates endpoint contract used by frontend" -Response $candidates -ExpectedStatus @(200) -Validator {
        param($r)
        if ($null -eq $r.json) { return @{ ok = $false; note = "response is not JSON" } }
        if (-not ($r.json.items -is [System.Array])) { return @{ ok = $false; note = "missing items array" } }
        if ($r.json.items.Count -eq 0) { return @{ ok = $true; note = "empty items" } }
        $first = $r.json.items[0]
        $needed = @(
            "key", "vm_name", "size_gb", "source_ds", "target_ds",
            "source_used_pct", "target_used_pct", "source_used_after_pct", "target_used_after_pct",
            "score", "reason"
        )
        $missing = @()
        foreach ($k in $needed) {
            if ($null -eq $first.$k -and -not ($first.PSObject.Properties.Name -contains $k)) {
                $missing += $k
            }
        }
        return @{ ok = ($missing.Count -eq 0); note = if ($missing.Count -eq 0) { "ok" } else { "missing fields: $($missing -join ', ')" } }
    }

    $typedDetail = Invoke-Api -Method "GET" -Path "/api/analytics/clusters/$targetClusterId/detail"
    $results += Add-Check -Id "AN-DETAIL-001" -Severity "P1" -Description "Typed analytics detail endpoint" -Response $typedDetail -ExpectedStatus @(200)

    $metrics = Invoke-Api -Method "GET" -Path "/api/analytics/clusters/$targetClusterId/datastores/metrics"
    $results += Add-Check -Id "AN-METRICS-001" -Severity "P1" -Description "Datastore metrics endpoint" -Response $metrics -ExpectedStatus @(200)

    $trends = Invoke-Api -Method "GET" -Path "/api/analytics/clusters/$targetClusterId/trends"
    $results += Add-Check -Id "AN-TRENDS-001" -Severity "P2" -Description "Cluster trends endpoint" -Response $trends -ExpectedStatus @(200)

    $pendingTyped = Invoke-Api -Method "GET" -Path "/api/analytics/clusters/$targetClusterId/recommendations/pending"
    $results += Add-Check -Id "AN-PENDING-001" -Severity "P2" -Description "Typed pending recommendations endpoint" -Response $pendingTyped -ExpectedStatus @(200)

    $stats = Invoke-Api -Method "GET" -Path "/api/analytics/clusters/$targetClusterId/recommendations/stats"
    $results += Add-Check -Id "AN-STATS-001" -Severity "P2" -Description "Recommendation stats endpoint" -Response $stats -ExpectedStatus @(200)

    $risk = Invoke-Api -Method "GET" -Path "/api/analytics/clusters/$targetClusterId/risk"
    $results += Add-Check -Id "AN-RISK-001" -Severity "P1" -Description "Cluster risk endpoint" -Response $risk -ExpectedStatus @(200)
} else {
    $results += Add-Skip -Id "CLUSTER-DETAIL-001" -Severity "P1" -Description "Cluster detail contract fields" -Reason "no cluster id available"
    $results += Add-Skip -Id "RECS-CLUSTER-001" -Severity "P1" -Description "Cluster recommendations endpoint returns list" -Reason "no cluster id available"
    $results += Add-Skip -Id "CAND-CLUSTER-001" -Severity "P1" -Description "Heuristic candidates endpoint contract used by frontend" -Reason "no cluster id available"
    $results += Add-Skip -Id "AN-DETAIL-001" -Severity "P1" -Description "Typed analytics detail endpoint" -Reason "no cluster id available"
    $results += Add-Skip -Id "AN-METRICS-001" -Severity "P1" -Description "Datastore metrics endpoint" -Reason "no cluster id available"
    $results += Add-Skip -Id "AN-TRENDS-001" -Severity "P2" -Description "Cluster trends endpoint" -Reason "no cluster id available"
    $results += Add-Skip -Id "AN-PENDING-001" -Severity "P2" -Description "Typed pending recommendations endpoint" -Reason "no cluster id available"
    $results += Add-Skip -Id "AN-STATS-001" -Severity "P2" -Description "Recommendation stats endpoint" -Reason "no cluster id available"
    $results += Add-Skip -Id "AN-RISK-001" -Severity "P1" -Description "Cluster risk endpoint" -Reason "no cluster id available"
}

Write-Host ""
Write-Host "QA Smoke Results ($ApiBase)" -ForegroundColor Cyan
$results | Format-Table id, severity, result, status, expected, elapsed_ms, note -AutoSize

$runtimeDir = Split-Path -Parent $OutFile
if ($runtimeDir -and -not (Test-Path $runtimeDir)) {
    New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null
}
$results | ConvertTo-Json -Depth 6 | Set-Content -Path $OutFile -Encoding utf8
Write-Host ""
Write-Host "Saved report: $OutFile"

$fails = @($results | Where-Object { $_.result -eq "FAIL" }).Count
if ($fails -gt 0) {
    Write-Host "Total FAIL: $fails" -ForegroundColor Red
    exit 1
}

Write-Host "All asserted checks passed." -ForegroundColor Green
exit 0
