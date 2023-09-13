
from .core import script


def activate_bip345_vault():
    """
    Patches in script changes necessary for use of BIP-345 (OP_VAULT).
    """
    script.OP_VAULT = script.CScriptOp(0xbb)
    script.OP_VAULT_RECOVER = script.CScriptOp(0xbc)

    script.OPCODE_NAMES[script.OP_VAULT] = 'OP_VAULT'
    script.OPCODE_NAMES[script.OP_VAULT_RECOVER] = 'OP_VAULT_RECOVER'
