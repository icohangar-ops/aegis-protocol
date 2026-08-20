"""
Executor Agent — Signs and broadcasts emergency pause() transactions.
In production: Web3.py with real EVM chain.
In mock mode: Simulates successful on-chain execution.
"""

import os
import time
import json
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class ExecutionStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ExecutionResult:
    status: ExecutionStatus
    tx_hash: str
    block_number: int
    gas_used: int
    gas_cost_eth: float
    execution_time_ms: int
    chain: str
    contract_address: str
    error: Optional[str] = None

    def __str__(self):
        if self.status == ExecutionStatus.SUCCESS:
            return (
                f"\n{'='*60}"
                f"\n  EXECUTOR — TRANSACTION BROADCAST"
                f"\n{'='*60}"
                f"\n  Status    : ✅ SUCCESS"
                f"\n  TX Hash   : {self.tx_hash}"
                f"\n  Block     : {self.block_number:,}"
                f"\n  Gas Used  : {self.gas_used:,}"
                f"\n  Gas Cost  : {self.gas_cost_eth:.6f} ETH"
                f"\n  Chain     : {self.chain}"
                f"\n  Contract  : {self.contract_address}"
                f"\n  Time      : {self.execution_time_ms}ms"
                f"\n{'='*60}"
            )
        elif self.status == ExecutionStatus.SKIPPED:
            return f"\n  ✅ EXECUTOR: SKIPPED — No pause required (false alarm confirmed)"
        else:
            return f"\n  ❌ EXECUTOR: FAILED — {self.error}"


class ExecutorAgent:
    """Broadcasts emergency pause() transactions to EVM chains."""

    VAULT_ABI = '[{"inputs":[],"name":"triggerEmergencyPause","outputs":[],"stateMutability":"nonpayable","type":"function"}]'

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        private_key: Optional[str] = None,
        vault_address: Optional[str] = None,
        chain: str = "sepolia",
    ):
        self.rpc_url = rpc_url or os.getenv("SEPOLIA_RPC_URL")
        self.private_key = private_key or os.getenv("AEGIS_PRIVATE_KEY")
        self.vault_address = vault_address or os.getenv("VAULT_CONTRACT_ADDRESS")
        self.chain = chain
        self._w3 = None
        self._account = None
        self._contract = None

    def _init_web3(self):
        if self._w3 is None and self.rpc_url and self.private_key:
            from web3 import Web3
            self._w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            self._account = self._w3.eth.account.from_key(self.private_key)
            abi = json.loads(self.VAULT_ABI)
            self._contract = self._w3.eth.contract(
                address=self._w3.to_checksum_address(self.vault_address),
                abi=abi,
            )

    def execute_pause(self, should_pause: bool, mock: bool = False) -> ExecutionResult:
        if not should_pause:
            return ExecutionResult(
                status=ExecutionStatus.SKIPPED,
                tx_hash="N/A",
                block_number=0,
                gas_used=0,
                gas_cost_eth=0.0,
                execution_time_ms=0,
                chain=self.chain,
                contract_address=self.vault_address or "0x...",
            )

        start = time.time()

        if mock:
            time.sleep(0.3)
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                tx_hash="0xaegis_pause_tx_" + hex(int(time.time()))[2:],
                block_number=5_892_342,
                gas_used=48_721,
                gas_cost_eth=0.001461,
                execution_time_ms=int((time.time() - start) * 1000),
                chain=self.chain,
                contract_address=self.vault_address or "0x742d35Cc6634C0532925a3b844Bc9e7595f5bA16",
            )

        # Live execution
        self._init_web3()
        if not self._contract:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                tx_hash="",
                block_number=0,
                gas_used=0,
                gas_cost_eth=0.0,
                execution_time_ms=0,
                chain=self.chain,
                contract_address=self.vault_address or "0x...",
                error="Web3 not initialized — check RPC URL and private key",
            )

        try:
            tx = self._contract.functions.triggerEmergencyPause().build_transaction({
                "from": self._account.address,
                "nonce": self._w3.eth.get_transaction_count(self._account.address),
                "gas": 100000,
                "maxFeePerGas": self._w3.to_wei("30", "gwei"),
                "maxPriorityFeePerGas": self._w3.to_wei("2", "gwei"),
            })
            signed = self._w3.eth.account.sign_transaction(tx, self.private_key)
            tx_hash = self._w3.eth.send_raw_transaction(signed.rawTransaction)
            receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)

            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                tx_hash=tx_hash.hex(),
                block_number=receipt.blockNumber,
                gas_used=receipt.gasUsed,
                gas_cost_eth=float(receipt.gasUsed * receipt.effectiveGasPrice) / 1e18,
                execution_time_ms=int((time.time() - start) * 1000),
                chain=self.chain,
                contract_address=self.vault_address,
            )
        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                tx_hash="",
                block_number=0,
                gas_used=0,
                gas_cost_eth=0.0,
                execution_time_ms=int((time.time() - start) * 1000),
                chain=self.chain,
                contract_address=self.vault_address or "0x...",
                error=str(e),
            )
