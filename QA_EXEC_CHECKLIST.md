# SDRS Manager QA Checklist (Executavel)

## 1. Subir aplicacao

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Verificacoes iniciais:

```powershell
Invoke-WebRequest http://127.0.0.1:8010/api/health -UseBasicParsing
Invoke-WebRequest http://127.0.0.1:5500/index.html -UseBasicParsing
```

## 2. Rodar smoke QA automatizado

Execucao padrao:

```powershell
powershell -ExecutionPolicy Bypass -File .\qa_smoke.ps1
```

Execucao forcando cluster especifico:

```powershell
powershell -ExecutionPolicy Bypass -File .\qa_smoke.ps1 -ApiBase http://127.0.0.1:8010 -ClusterId group-pod-21
```

Relatorio gerado:

- `.runtime/qa_smoke_results.json`

Regras do script:

- Falha (`exit 1`) se qualquer check assertivo retornar `FAIL`.
- `SKIP` quando nao houver cluster para validar endpoints de detalhe.
- O script nao grava `.env` e nao aplica moviments reais.
- O script chama `apply/dismiss` com chave dummy apenas para validar comportamento de `read_only`.

## 3. Testes manuais P0/P1 (comandos prontos)

### 3.1 Health + read-only

```powershell
Invoke-RestMethod http://127.0.0.1:8010/api/health -Method GET
```

Esperado:

- `status = "ok"`
- campo `read_only` presente

### 3.2 Guardas de read-only em apply/dismiss

```powershell
Invoke-RestMethod http://127.0.0.1:8010/api/clusters/group-pod-21/recs/qa-key/apply -Method POST
Invoke-RestMethod http://127.0.0.1:8010/api/clusters/group-pod-21/recs/qa-key/dismiss -Method POST
```

Esperado com `READ_ONLY_MODE=true`:

- HTTP `403` em ambos

### 3.3 Snapshot analitico

```powershell
Invoke-RestMethod http://127.0.0.1:8010/api/analytics/dashboard/snapshot -Method GET
```

Esperado:

- HTTP `200`
- campo `global` no payload

### 3.4 Contrato de candidatos (usado no frontend)

```powershell
Invoke-RestMethod "http://127.0.0.1:8010/api/clusters/group-pod-21/candidates?limit=10" -Method GET
```

Esperado:

- `items` array
- itens com chaves: `key`, `vm_name`, `size_gb`, `source_ds`, `target_ds`, `score`

## 4. Testes manuais de seguranca (recomendado em ambiente de homologacao)

Objetivo: verificar que endpoints sensiveis exigem autenticacao. Hoje o codigo atual ainda precisa endurecimento.

### 4.1 Tentativa sem auth no endpoint de configuracao

```powershell
$body = @{
  host = "vc.invalid.local"
  user = "readonly@vsphere.local"
  password = "dummy"
  verify_ssl = $false
} | ConvertTo-Json

Invoke-WebRequest -Uri http://127.0.0.1:8010/api/vcenter/config -Method POST -ContentType "application/json" -Body $body -UseBasicParsing
```

Esperado alvo de seguranca:

- HTTP `401` ou `403`

## 5. Matriz curta para regressao rapida

| ID | Cenario | Entrada | Esperado | Prioridade |
|---|---|---|---|---|
| API-HEALTH-001 | Health e flag read_only | `GET /api/health` | `200` e `read_only` presente | P0 |
| READONLY-APPLY-001 | Bloqueio de escrita | `POST /api/clusters/{id}/recs/{k}/apply` | `403` em modo read-only | P0 |
| READONLY-DISMISS-001 | Bloqueio de escrita | `POST /api/clusters/{id}/recs/{k}/dismiss` | `403` em modo read-only | P0 |
| AN-SNAPSHOT-001 | Snapshot tipado | `GET /api/analytics/dashboard/snapshot` | `200` com `global` | P0 |
| CLUSTER-DETAIL-001 | Contrato de detalhe | `GET /api/clusters/{id}` | Campos de datastore completos | P1 |
| CAND-CLUSTER-001 | Contrato de candidatos | `GET /api/clusters/{id}/candidates` | `items` com campos usados na UI | P1 |

## 6. Encerrar aplicacao

```powershell
powershell -ExecutionPolicy Bypass -File .\stop.ps1
```
