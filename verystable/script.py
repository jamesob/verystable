import io

from . import core
from .core import key, script
from .core.script import CScript, CScriptNum


class CTransaction(core.messages.CTransaction):
    def pformat(self) -> str:
        s = f"CTransaction: (nVersion={self.nVersion})\n"
        s += "  vin:\n"
        for i, inp in enumerate(self.vin):
            s += f"    - [{i}] {inp}\n"
        s += "  vout:\n"
        for i, out in enumerate(self.vout):
            s += f"    - [{i}] {out}\n"

        s += "  witnesses:\n"
        for i, wit in enumerate(self.wit.vtxinwit):
            s += f"    - [{i}]\n"
            for j, item in enumerate(wit.scriptWitness.stack):
                if type(item) == bytes:
                    scriptstr = repr(CScript([item]))
                elif type(item) in {CScript, CScriptNum}:
                    scriptstr = repr(item)
                else:
                    raise NotImplementedError

                s += f"      - [{i}.{j}] {scriptstr}\n"

        s += f"  nLockTime: {self.nLockTime}\n"

        return s

    def pprint(self) -> None:
        print(self.pformat())

    @classmethod
    def fromhex(cls, h: str) -> "CTransaction":
        tx = cls()
        tx.deserialize(io.BytesIO(bytes.fromhex(h)))
        return tx

    def tohex(self) -> str:
        return self.serialize().hex()


__TaprootInfo = core.script.TaprootInfo


class TaprootInfo(__TaprootInfo):
    @property
    def p2tr_address(self) -> str:
        return core.address.output_key_to_p2tr(self.output_pubkey)

    def controlblock_for_script_spend(self, script_name: str) -> bytes:
        leaf = self.leaves[script_name]
        return (
            bytes([leaf.version + self.negflag])
            + self.internal_pubkey
            + leaf.merklebranch
        )


core.script.TaprootInfo = TaprootInfo


def taproot_from_privkey(pk: key.ECKey, scripts=None) -> script.TaprootInfo:
    x_only, _ = key.compute_xonly_pubkey(pk.get_bytes())
    return script.taproot_construct(x_only, scripts=scripts)
