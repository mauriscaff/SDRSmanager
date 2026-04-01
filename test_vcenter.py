import asyncio
import logging

from backend.vcenter import VCenterClient, VCenterClientError


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)


async def main() -> None:
    client: VCenterClient | None = None
    try:
        client = VCenterClient()
        token = await client.authenticate()
        print(f"Autenticado com sucesso. Token length={len(token)}")
    except VCenterClientError as exc:
        print(f"Erro controlado do cliente: {exc}")
    except Exception as exc:  # noqa: BLE001
        print(f"Erro inesperado: {exc}")
        raise
    finally:
        if client is not None:
            await client.close()


if __name__ == "__main__":
    asyncio.run(main())
