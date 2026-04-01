from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx
from dotenv import load_dotenv

logger = logging.getLogger("sdrs-manager.vcenter")


class VCenterClientError(Exception):
    """Erro controlado para falhas de comunicação/autenticação com o vCenter."""


def _parse_bool(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class SecondaryVCenterConfig:
    name: str
    host: str
    user: str
    password: str
    verify_ssl: bool


def load_secondary_vcenter_configs(load_env_file: bool = True) -> tuple[list[SecondaryVCenterConfig], list[str]]:
    """
    Formato:
    VCENTER_SECONDARY_NAMES=S2002,S2003
    VCENTER_S2002_HOST=...
    VCENTER_S2002_USER=...
    VCENTER_S2002_PASSWORD=...
    VCENTER_S2002_VERIFY_SSL=false
    """
    if load_env_file:
        load_dotenv()

    raw_names = (os.getenv("VCENTER_SECONDARY_NAMES") or "").strip()
    if not raw_names:
        return [], []

    warnings: list[str] = []
    configs: list[SecondaryVCenterConfig] = []
    names = [item.strip() for item in raw_names.split(",") if item.strip()]

    for name in names:
        key = name.upper()
        raw_host = (os.getenv(f"VCENTER_{key}_HOST") or "").strip()
        host = raw_host.replace("https://", "").replace("http://", "").rstrip("/")
        user = (os.getenv(f"VCENTER_{key}_USER") or "").strip()
        password = os.getenv(f"VCENTER_{key}_PASSWORD") or ""
        verify_ssl = _parse_bool(os.getenv(f"VCENTER_{key}_VERIFY_SSL"), default=True)

        if not host or not user or not password:
            warnings.append(f"Configuração secundária '{name}' incompleta; ignorando.")
            continue

        configs.append(
            SecondaryVCenterConfig(
                name=name,
                host=host,
                user=user,
                password=password,
                verify_ssl=verify_ssl,
            )
        )

    return configs, warnings


class VCenterClient:
    def __init__(
        self,
        timeout: float = 30.0,
        host: str | None = None,
        user: str | None = None,
        password: str | None = None,
        verify_ssl: bool | None = None,
        load_env_file: bool = True,
    ) -> None:
        if load_env_file:
            load_dotenv()

        raw_host = (host if host is not None else (os.getenv("VCENTER_HOST") or "")).strip()
        self.user = (user if user is not None else (os.getenv("VCENTER_USER") or "")).strip()
        self.password = password if password is not None else (os.getenv("VCENTER_PASSWORD") or "")
        self.verify_ssl = (
            bool(verify_ssl)
            if verify_ssl is not None
            else _parse_bool(os.getenv("VCENTER_VERIFY_SSL"), default=True)
        )

        if not raw_host:
            raise VCenterClientError("VCENTER_HOST não configurado.")
        if not self.user:
            raise VCenterClientError("VCENTER_USER não configurado.")
        if not self.password:
            raise VCenterClientError("VCENTER_PASSWORD não configurado.")

        normalized_host = raw_host.replace("https://", "").replace("http://", "").rstrip("/")
        self.host = normalized_host
        self.base_url = f"https://{self.host}"

        self.session_token: str | None = None

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            verify=self.verify_ssl,
            timeout=httpx.Timeout(timeout, connect=15.0),
            headers={
                "Accept": "application/json",
            },
        )

        logger.info(
            "VCenterClient inicializado para host=%s verify_ssl=%s",
            self.host,
            self.verify_ssl,
        )

    async def authenticate(self) -> str:
        """
        Cria uma sessão no vCenter via POST /api/session.
        """
        try:
            response = await self._client.post(
                "/api/session",
                auth=(self.user, self.password),
            )

            if response.status_code in {401, 403}:
                logger.error(
                    "Falha de autenticação no vCenter host=%s status=%s",
                    self.host,
                    response.status_code,
                )
                raise VCenterClientError("Falha de autenticação no vCenter. Verifique usuário e senha.")

            response.raise_for_status()

            token = response.json()
            if not isinstance(token, str) or not token.strip():
                logger.error("Resposta de autenticação sem token válido no host=%s", self.host)
                raise VCenterClientError("O vCenter retornou uma sessão inválida.")

            self.session_token = token
            self._client.headers["vmware-api-session-id"] = token

            logger.info("Autenticação no vCenter realizada com sucesso host=%s", self.host)
            return token

        except httpx.ConnectTimeout as exc:
            logger.exception("Timeout de conexão ao autenticar no vCenter host=%s", self.host)
            raise VCenterClientError("Timeout ao conectar no vCenter.") from exc

        except httpx.ReadTimeout as exc:
            logger.exception("Timeout de leitura ao autenticar no vCenter host=%s", self.host)
            raise VCenterClientError("O vCenter demorou demais para responder.") from exc

        except httpx.ConnectError as exc:
            logger.exception("Erro de conexão ao autenticar no vCenter host=%s", self.host)
            raise VCenterClientError("Não foi possível conectar ao vCenter.") from exc

        except httpx.HTTPStatusError as exc:
            logger.exception(
                "Erro HTTP ao autenticar no vCenter host=%s status=%s",
                self.host,
                exc.response.status_code,
            )
            raise VCenterClientError(
                f"Erro HTTP ao autenticar no vCenter: {exc.response.status_code}."
            ) from exc

        except httpx.RequestError as exc:
            logger.exception("Erro de requisição ao autenticar no vCenter host=%s", self.host)
            raise VCenterClientError("Erro de comunicação com o vCenter.") from exc

        except ValueError as exc:
            logger.exception("Resposta JSON inválida na autenticação host=%s", self.host)
            raise VCenterClientError("Resposta inválida recebida do vCenter.") from exc

    async def get(self, path: str) -> Any:
        """
        Envia GET autenticado.
        Se receber 401, reautentica uma vez e tenta novamente.
        """
        return await self._request("GET", path)

    async def post(self, path: str, json: dict[str, Any] | None = None) -> Any:
        """
        Envia POST autenticado.
        Se receber 401, reautentica uma vez e tenta novamente.
        """
        return await self._request("POST", path, json=json)

    async def _request(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | None = None,
        retry_on_401: bool = True,
    ) -> Any:
        normalized_path = path if path.startswith("/") else f"/{path}"

        if not self.session_token:
            await self.authenticate()

        try:
            response = await self._client.request(
                method=method,
                url=normalized_path,
                json=json,
            )

            if response.status_code == 401 and retry_on_401:
                logger.warning(
                    "Sessão expirada ou inválida no host=%s, reautenticando e tentando novamente.",
                    self.host,
                )
                await self.authenticate()

                response = await self._client.request(
                    method=method,
                    url=normalized_path,
                    json=json,
                )

            if response.status_code in {401, 403}:
                logger.error(
                    "Acesso negado no vCenter host=%s method=%s path=%s status=%s",
                    self.host,
                    method,
                    normalized_path,
                    response.status_code,
                )
                raise VCenterClientError("Acesso negado pelo vCenter.")

            response.raise_for_status()

            if response.status_code == 204 or not response.content:
                return {"ok": True}

            content_type = response.headers.get("content-type", "").lower()
            if "application/json" in content_type:
                return response.json()

            return {"raw": response.text}

        except VCenterClientError:
            raise

        except httpx.ConnectTimeout as exc:
            logger.exception(
                "Timeout de conexão no vCenter host=%s method=%s path=%s",
                self.host,
                method,
                normalized_path,
            )
            raise VCenterClientError("Timeout ao conectar no vCenter.") from exc

        except httpx.ReadTimeout as exc:
            logger.exception(
                "Timeout de leitura no vCenter host=%s method=%s path=%s",
                self.host,
                method,
                normalized_path,
            )
            raise VCenterClientError("O vCenter demorou demais para responder.") from exc

        except httpx.ConnectError as exc:
            logger.exception(
                "Erro de conexão no vCenter host=%s method=%s path=%s",
                self.host,
                method,
                normalized_path,
            )
            raise VCenterClientError("Não foi possível conectar ao vCenter.") from exc

        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code if exc.response else "unknown"
            logger.exception(
                "Erro HTTP no vCenter host=%s method=%s path=%s status=%s",
                self.host,
                method,
                normalized_path,
                status_code,
            )
            raise VCenterClientError(f"Erro HTTP retornado pelo vCenter: {status_code}.") from exc

        except httpx.RequestError as exc:
            logger.exception(
                "Erro de requisição no vCenter host=%s method=%s path=%s",
                self.host,
                method,
                normalized_path,
            )
            raise VCenterClientError("Erro de comunicação com o vCenter.") from exc

        except ValueError as exc:
            logger.exception(
                "Resposta inválida do vCenter host=%s method=%s path=%s",
                self.host,
                method,
                normalized_path,
            )
            raise VCenterClientError("Resposta inválida recebida do vCenter.") from exc

    async def close(self) -> None:
        """
        Encerra a sessão no vCenter via DELETE /api/session e fecha o AsyncClient.
        """
        try:
            if self.session_token:
                response = await self._client.delete("/api/session")
                if response.status_code not in {200, 204, 401}:
                    logger.warning(
                        "DELETE /api/session retornou status inesperado host=%s status=%s",
                        self.host,
                        response.status_code,
                    )
        except httpx.RequestError:
            logger.exception("Erro ao encerrar sessão no vCenter host=%s", self.host)
        finally:
            self.session_token = None
            self._client.headers.pop("vmware-api-session-id", None)
            await self._client.aclose()
            logger.info("VCenterClient finalizado host=%s", self.host)
