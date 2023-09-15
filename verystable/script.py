from .core import key, script
from .core.script import CTransaction, CScript, CScriptNum, TaprootInfo


def pprint_tx(tx: CTransaction, should_print: bool = True) -> str:
    s = f"CTransaction: (nVersion={tx.nVersion})\n"
    s += "  vin:\n"
    for i, inp in enumerate(tx.vin):
        s += f"    - [{i}] {inp}\n"
    s += "  vout:\n"
    for i, out in enumerate(tx.vout):
        s += f"    - [{i}] {out}\n"

    s += "  witnesses:\n"
    for i, wit in enumerate(tx.wit.vtxinwit):
        s += f"    - [{i}]\n"
        for j, item in enumerate(wit.scriptWitness.stack):
            if type(item) == bytes:
                scriptstr = repr(CScript([item]))
            elif type(item) in {CScript, CScriptNum}:
                scriptstr = repr(item)
            else:
                raise NotImplementedError

            s += f"      - [{i}.{j}] {scriptstr}\n"

    s += f"  nLockTime: {tx.nLockTime}\n"

    if should_print:
        print(s)
    return s


def controlblock_for_script_spend(tr: TaprootInfo, script_name: str) -> bytes:
    leaf = tr.leaves[script_name]
    return (
        bytes([leaf.version + tr.negflag]) + tr.internal_pubkey + leaf.merklebranch
    )


def taproot_from_privkey(pk: key.ECKey, scripts=None) -> script.TaprootInfo:
    x_only, _ = key.compute_xonly_pubkey(pk.get_bytes())
    return script.taproot_construct(x_only, scripts=scripts)
