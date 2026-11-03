import json, os, sys
data = {"cwd": os.getcwd(), "py": sys.version.split()[0]}
print(json.dumps(data))
