import json, subprocess, sys, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
def tier(p):
    out = subprocess.run([sys.executable, str(root/'scanner/scan.py'), str(root/p)],
                         capture_output=True, text=True)
    return json.loads(out.stdout)['tier']
cases = {'examples/t0-benign':'T0','examples/t3-persistence':'T3','examples/t4-remote-exec':'T4','examples/t0-self-inspecting':'T0'}
bad = {k:(tier(k),v) for k,v in cases.items() if tier(k)!=v}
if bad:
    print('FAIL', bad); sys.exit(1)
print('ok — tiers:', {k:tier(k) for k in cases})
