import json
import datetime
import pathlib

from . import wallet, script


class Json:
    """
    JSON serialization that knows how to deal with bytes, dates, and various bitcoin
    structures.
    """

    # Append to this dynamically as needed to allow certain classes to be
    # serialized/deserialized.
    ALLOWED_CLASSES = {c.__name__: c for c in (wallet.Outpoint,)}

    @classmethod
    def add_allowed_classes(cls, *classes):
        for c in classes:
            cls.ALLOWED_CLASSES[c.__name__] = c

    class Encoder(json.JSONEncoder):

        def default(self, o):
            if isinstance(o, bytes):
                return {"_type": "hex", "_val": o.hex()}
            elif isinstance(o, datetime.datetime):
                return {"_type": "datetime", "_val": o.isoformat()}
            elif isinstance(o, pathlib.Path):
                return {"_type": "path", "_val": str(o)}
            elif isinstance(o, script.CScript):
                return {"_type": "CScript", "_val": o.hex()}
            elif isinstance(o, script.CTransaction):
                return {"_type": "CTransaction", "_val": o.tohex()}

            elif cls := Json.ALLOWED_CLASSES.get(o.__class__.__name__):
                d = dict(o.__dict__)
                if allowed_fields := getattr(o, "__dataclass_fields__", []):
                    d = {k: v for k, v in o.__dict__.items() if k in allowed_fields}
                for ex in getattr(o, "_json_exclude", []):
                    d.pop(ex)
                d["_class"] = cls.__name__
                return d

            return super().default(o)

    @classmethod
    def object_hook(cls, o: dict) -> object:
        if ObjectClass := cls.ALLOWED_CLASSES.get(o.get("_class", "")):
            o.pop("_class")
            return ObjectClass(**o)

        if (type_ := o.get("_type")) and (val := o.get("_val")) is not None:
            match type_:
                case "hex":
                    return bytes.fromhex(val)
                case "path":
                    return pathlib.Path(val)
                case "datetime":
                    return datetime.datetime.fromisoformat(val)
                case "CScript":
                    return script.CScript(bytes.fromhex(val))
                case "CTransaction":
                    return script.CTransaction.fromhex(val)

        return o

    @classmethod
    def dumps(cls, *args, **kwargs):
        return json.dumps(*args, cls=cls.Encoder, **kwargs)

    @classmethod
    def loads(cls, *args, **kwargs):
        return json.loads(*args, object_hook=Json.object_hook, **kwargs)
