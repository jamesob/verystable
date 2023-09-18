import time
import typing as t
from dataclasses import dataclass
from functools import cached_property

from . import core
from .rpc import BitcoinRPC, JSONRPCError
from .core.script import CScript
from .core.messages import COutPoint, CTxOut, CTxIn

import logging

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Outpoint:
    txid: str
    n: int

    def __str__(self):
        return f"{self.txid}:{self.n}"


def btc_to_sats(btc) -> int:
    return int(btc * core.messages.COIN)


def txid_to_int(txid: str) -> int:
    return int.from_bytes(bytes.fromhex(txid), byteorder="big")


@dataclass(frozen=True)
class Utxo:
    outpoint: Outpoint
    address: str
    value_sats: int
    height: int

    @cached_property
    def scriptPubKey(self) -> CScript:
        return core.address.address_to_scriptpubkey(self.address)

    @cached_property
    def coutpoint(self) -> COutPoint:
        return COutPoint(txid_to_int(self.outpoint.txid), self.outpoint.n)

    @cached_property
    def output(self) -> CTxOut:
        return CTxOut(nValue=self.value_sats, scriptPubKey=self.scriptPubKey)

    @cached_property
    def as_txin(self) -> CTxIn:
        return CTxIn(self.coutpoint)

    @property
    def outpoint_str(self) -> str:
        return str(self.outpoint)


@dataclass
class Spend:
    spent_utxo: Utxo
    height: int
    tx: dict

    def __repr__(self) -> str:
        return (
            f"Spend(amt={self.spent_utxo.value_sats} "
            f"from_addr={self.spent_utxo.address}, height={self.height})"
        )


def get_confs_for_txid(
    rpc: BitcoinRPC, target_txid: str, min_height: int = 0
) -> int | None:
    """Return the number of confirmations for a transaction."""
    height = rpc.getblockcount()
    found_height = None
    while min_height is None or height >= min_height:
        blk = rpc.getblock(rpc.getblockhash(height), 1)
        height -= 1

        for txid in blk["tx"]:
            if txid == target_txid:
                found_height = blk["height"]

    if found_height is None:
        return None

    return rpc.getblockcount() - found_height + 1


def get_relevant_blocks(
    rpc: BitcoinRPC,
    addrs: t.Iterable[str],
    startheight: int = 0,
    max_wait_secs: int = 5,
) -> list[tuple[int, dict]]:
    """
    Given some addresses, return height/block pairs with relevant activity.
    """
    scanarg = [f"addr({addr})" for addr in addrs]

    def wait_for_scan_end(to_wait_secs: int = max_wait_secs):
        while (status := rpc.scanblocks("status")) and to_wait_secs >= 0:
            log.info("scanblocks in progress: %s", status)
            to_wait_secs -= 1
            time.sleep(1)

    wait_for_scan_end()

    def scanblocks() -> dict:
        return rpc._call("scanblocks", "start", scanarg, startheight, timeout=10_000)

    try:
        got = scanblocks()
    except JSONRPCError as e:
        if e.code == -8:
            # scan already in progress
            wait_for_scan_end()
            try:
                got = scanblocks()
            except JSONRPCError as e:
                log.exception("scanblocks call busy for too long")

    assert "relevant_blocks" in got

    heights_and_blocks = []
    for hash in set(got["relevant_blocks"]):
        block = rpc.getblock(hash, 2)
        heights_and_blocks.append((block["height"], block))

    return heights_and_blocks


def get_addr_history(
    rpc: BitcoinRPC,
    addr_watchlist: t.Iterable[str],
) -> tuple[set[Utxo], list[Spend]]:
    """
    Return all outstanding UTXOs associated with a set of addresses, and their spend
    history.
    """
    utxos: set[Utxo] = set()
    spent: list[Spend] = []
    heights_and_blocks = get_relevant_blocks(rpc, addr_watchlist)
    outpoint_to_utxo: dict[Outpoint, Utxo] = {}
    txids_to_watch: set[str] = set()

    for height, block in sorted(heights_and_blocks):
        for tx in block["tx"]:
            # Detect new utxos
            for vout in tx["vout"]:
                if (addr := vout.get("scriptPubKey", {}).get("address")) and (
                    addr in addr_watchlist
                ):
                    op = Outpoint(tx["txid"], vout["n"])
                    utxo = Utxo(op, addr, btc_to_sats(vout["value"]), height)
                    outpoint_to_utxo[op] = utxo
                    txids_to_watch.add(tx["txid"])
                    utxos.add(utxo)
                    log.info("found utxo (%s): %s", addr, utxo)

            # Detect spends
            for vin in filter(lambda vin: "txid" in vin, tx["vin"]):
                spent_txid = vin["txid"]
                if spent_txid not in txids_to_watch:
                    continue

                op = Outpoint(spent_txid, vin.get("vout"))

                if not (spent_utxo := outpoint_to_utxo.get(op)):
                    continue

                log.info("found spend of utxo %s", spent_utxo)
                spent.append(Spend(spent_utxo, height, tx))
                utxos.remove(spent_utxo)
                outpoint_to_utxo.pop(op)

    return utxos, spent
