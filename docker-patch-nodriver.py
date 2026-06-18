from pathlib import Path

import nodriver
from nodriver.core import config


config_path = Path(config.__file__)
source = config_path.read_text(encoding="utf-8")
needle = '"no-sandbox",\n                "no_sandbox",\n'
if needle not in source:
    raise SystemExit(f"nodriver add_argument guard not found in {config_path}")

patched = source.replace(needle, "", 1)
config_path.write_text(patched, encoding="utf-8")

print(f"patched nodriver {getattr(nodriver, '__version__', 'unknown')} at {config_path}")
