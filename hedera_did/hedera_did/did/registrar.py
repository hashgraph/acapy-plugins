"""Hedera DID registrar."""

from acapy_agent.wallet.base import BaseWallet, DIDInfo
from acapy_agent.wallet.key_type import ED25519, KeyTypes
from did_sdk_py.did.hedera_did_resolver import HederaDid
from hedera import PrivateKey

from ..client import get_client_provider
from ..config import Config
from .did_method import HEDERA


class HederaDIDRegistrar:
    """Hedera DID registrar."""

    def __init__(self, context):
        """Constructor."""
        self.context = context

        config = Config.from_settings(context.settings)

        network = config.network
        operator_id = config.operator_id
        operator_key_der = config.operator_key_der

        self._client_provider = get_client_provider(
            network, operator_id, operator_key_der
        )

    async def register(self, key_type, seed=None) -> DIDInfo:
        """Register Hedera DID."""
        async with self.context.session() as session:
            key_types = session.inject_or(KeyTypes)

            if not key_types:
                raise Exception("Failed to inject supported key types enum")

            key_type = key_types.from_key_type(key_type) or ED25519

            wallet = session.inject_or(BaseWallet)

            if not wallet:
                raise Exception("Failed to inject wallet instance")

            key_info = await wallet.create_key(ED25519, seed=seed)

            key_entry = await wallet._session.handle.fetch_key(name=key_info.verkey)

            if not key_entry:
                raise Exception("Could not fetch key")

            key = key_entry.key

            private_key_bytes = key.get_secret_bytes()

            hedera_did = HederaDid(
                self._client_provider,
                private_key_der=PrivateKey.fromBytes(private_key_bytes).toStringDER(),
            )

            await hedera_did.register()

            did = hedera_did.identifier

            info: DIDInfo = {
                "did": did,
                "verkey": key_info.verkey,
                "key_type": key_type.key_type,
            }

            await wallet._session.handle.insert(
                "did",
                did,
                value_json={
                    "did": did,
                    "method": HEDERA.method_name,
                    "verkey": key_info.verkey,
                    "verkey_type": key_type.key_type,
                    "metadata": {},
                },
                tags={
                    "method": HEDERA.method_name,
                    "verkey": key_info.verkey,
                    "verkey_type": key_type.key_type,
                },
            )

            return info
