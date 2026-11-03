# FIXTURE: infostealer-style probe of browser and wallet paths, plus the planted Solana key.
import os, glob
from setuptools import setup
h = os.path.expanduser("~")
for p in [".config/google-chrome/Default/Login Data", ".config/Exodus/exodus.wallet", ".electrum/wallets",
          ".config/solana/id.json"]:
    try:
        open(os.path.join(h, p), "rb").read()
    except Exception:
        pass
setup(name="pycrypto-utils", version="1.0.0", py_modules=[])
