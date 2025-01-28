"""
Calculator for making various transaction size computations.
"""

from verystable.core.script import OP_0, OP_1, OP_4, CScript
from verystable.core import messages
from verystable.core.messages import CTransaction, COutPoint, CTxOut, CTxIn


DUMMY_IN = CTxIn(COutPoint(int("0", 16), 0), nSequence=0)
DUMMY_HASH = b'\x00' * 32
DUMMY_SCHNORR_SIG = b'\x00' * 64


def make_ctv_lightning_close():
    """
    Sort of resembles
    https://github.com/lightning/bolts/blob/master/03-transactions.md#closing-transaction
    """
    tx = CTransaction()
    tx.version = 2
    tx.vin = [DUMMY_IN]
    tx.vout = [
        CTxOut(nValue=10000, scriptPubKey=CScript([OP_4, DUMMY_HASH])),
    ]
    witness = messages.CTxInWitness()
    tx.wit.vtxinwit = [witness]
    witness.scriptWitness.stack = [b'', DUMMY_SCHNORR_SIG, DUMMY_SCHNORR_SIG]

    return tx


def make_non_ctv_lightning_close():
    """
    Sort of resembles
    https://github.com/lightning/bolts/blob/master/03-transactions.md#closing-transaction
    """
    tx = CTransaction()
    tx.version = 2
    tx.vin = [DUMMY_IN]
    tx.vout = [
        CTxOut(nValue=10000, scriptPubKey=CScript([OP_1, DUMMY_HASH])),
        CTxOut(nValue=10000, scriptPubKey=CScript([OP_1, DUMMY_HASH])),
    ]
    witness = messages.CTxInWitness()
    tx.wit.vtxinwit = [witness]
    witness.scriptWitness.stack = [b'', DUMMY_SCHNORR_SIG, DUMMY_SCHNORR_SIG]

    return tx


"""
Compare using CTV vs. not to close lightning channels.
"""
ctv_size = make_ctv_lightning_close().get_vsize()
nonctv_size = make_non_ctv_lightning_close().get_vsize()

ctv_per_block = messages.MAX_BLOCK_WEIGHT // ctv_size
nonctv_per_block = messages.MAX_BLOCK_WEIGHT // nonctv_size


print(f"CTV txn: {ctv_size}vB")
print(f"non-CTV txn: {nonctv_size}vB")

print(f"CTV txns per block: {ctv_per_block}")
print(f"non-CTV txns per block: {nonctv_per_block}")

print(f"more per block with CTV: {100 * (ctv_per_block - nonctv_per_block) / nonctv_per_block:.1f}%")
