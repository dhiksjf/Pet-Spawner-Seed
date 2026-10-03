"""OWSI command line.

  owsi serve [--proxy-port 8080] [--api-port 9000] [--data-dir DIR]
  owsi status --url DIR
  owsi report --out report.md [--format md|html|json]
  owsi fuzz  --request-file req.txt --param id --payloads 1,2,3 [--mode sniper]
  owsi repeater --request-file req.txt
  owsi decode base64_decode "aGVsbG8="
  owsi analyze-jwt "<token>"
  owsi ca-install-hint
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .core import Application
from .http_model import HttpRequest
from .server import serve_control


def default_data_dir() -> str:
    return os.environ.get("OWSI_DATA_DIR") or os.path.join(
        os.path.expanduser("~"), ".owsi")


def _load_app(args) -> Application:
    return Application(getattr(args, "data_dir", None) or default_data_dir())


# ---------------------------------------------------------------------------
def cmd_serve(argv):
    ap = argparse.ArgumentParser(prog="owsi serve")
    ap.add_argument("--proxy-port", type=int, default=8080)
    ap.add_argument("--api-port", type=int, default=9000)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--data-dir", default=default_data_dir())
    ap.add_argument("--no-proxy", action="store_true")
    a = ap.parse_args(argv)
    app = _load_app(a)
    if not a.no_proxy:
        try:
            app.proxy.start((a.host, a.proxy_port))
        except OSError as e:
            print(f"[owsi] proxy could not start on :{a.proxy_port}: {e}",
                  file=sys.stderr)
    srv = serve_control(app, (a.host, a.api_port))
    print(f"""
  OMEGA Web Security Interceptor v1 — running locally
  ---------------------------------------------------------
  Dashboard / API   http://{a.host}:{a.api_port}
  HTTP proxy        {"http://%s:%d" % (a.host, a.proxy_port) if not a.no_proxy else 'disabled'}
  CA certificate    {app.ca.ca_cert_path}
                    (install into your browser/OS trust store to enable HTTPS
                     interception; fingerprint {app.ca.fingerprint_sha256[:32]}…)
  Policy mode       {app.policy.mode}  ← set targets & mode in the dashboard
  Data directory    {a.data_dir}
  ---------------------------------------------------------
  Ctrl-C to stop. Nothing leaves this machine except traffic you send.
""")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[owsi] shutting down")
        app.proxy.stop()
        srv.shutdown()


def cmd_status(argv):
    ap = argparse.ArgumentParser(prog="owsi status")
    ap.add_argument("--data-dir", default=default_data_dir())
    ap.add_argument("--api", default="", help="query a running instance instead")
    a = ap.parse_args(argv)
    if a.api:
        import httpx
        r = httpx.get(f"{a.api.rstrip('/')}/api/status", timeout=5)
        print(json.dumps(r.json(), indent=2)[:4000])
        return 0
    app = _load_app(a)
    st = {
        "history": app.db.count_history(),
        "findings": len(app.db.list_findings()),
        "wsSessions": len(app.db.list_ws_sessions()),
        "policyMode": app.policy.mode,
        "ca": app.ca.ca_cert_path,
    }
    print(json.dumps(st, indent=2))
    return 0


def cmd_report(argv):
    ap = argparse.ArgumentParser(prog="owsi report")
    ap.add_argument("--data-dir", default=default_data_dir())
    ap.add_argument("--out", required=True)
    ap.add_argument("--format", default="", choices=["", "md", "html", "json"])
    ap.add_argument("--hosts", default="")
    a = ap.parse_args(argv)
    from .report import build_report
    app = _load_app(a)
    fmt = a.format or os.path.splitext(a.out)[1].lstrip(".") or "md"
    rep = build_report(app, scope_hosts=[h for h in a.hosts.split(",") if h])
    blob = {"md": rep["markdown"], "html": rep["html"]}.get(fmt) \
        or json.dumps(rep, indent=2)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(blob)
    print(f"wrote {a.out} ({fmt}, {rep['findingCount']} findings)")
    return 0


def cmd_repeater(argv):
    ap = argparse.ArgumentParser(prog="owsi repeater")
    ap.add_argument("--request-file", required=True)
    ap.add_argument("--data-dir", default=default_data_dir())
    a = ap.parse_args(argv)
    app = _load_app(a)
    raw = open(a.request_file, "rb").read()
    req = HttpRequest.parse(raw)
    resp = app.repeater.send(req)
    sys.stdout.buffer.write(resp.raw() or
                            f"ERROR: {resp.error}".encode())
    return 0 if resp.status else 1


def cmd_fuzz(argv):
    ap = argparse.ArgumentParser(prog="owsi fuzz")
    ap.add_argument("--request-file", required=True)
    ap.add_argument("--param", required=True)
    ap.add_argument("--location", default="",
                    help="query|body|json|cookie (auto-detected if omitted)")
    ap.add_argument("--payloads", required=True,
                    help="comma separated values, or @file with one payload per line")
    ap.add_argument("--mode", default="sniper", choices=["sniper", "battering-ram"])
    ap.add_argument("--data-dir", default=default_data_dir())
    a = ap.parse_args(argv)
    app = _load_app(a)
    raw = open(a.request_file, "rb").read().decode("utf-8", "replace")
    req = HttpRequest.parse(raw.encode("iso-8859-1"))
    locs = dict(req.param_locations())
    location = a.location or locs.get(a.param, "query")
    if a.payloads.startswith("@"):
        payloads = [ln.strip() for ln in open(a.payloads[1:]) if ln.strip()]
    else:
        payloads = [p for p in a.payloads.split(",") if p]
    jid = f"cli{int(time.time()) % 10**6:x}"
    from .modules import FuzzJob
    job = FuzzJob(jid, req, [{"name": a.param, "location": location}],
                  payloads, a.mode)
    job.total = len(payloads)
    app.fuzzer.jobs[jid] = job
    app.policy.approve_action(jid)      # CLI invocation is explicit approval
    app.fuzzer._run(job)
    print(f"{'status':>7} {'len':>8}  payload")
    for r in job.results[1:]:
        print(f"{r.get('status','ERR'):>7} {r.get('length',0):>8}  "
              f"{r.get('label','')}" +
              (f"   << {r['anomaly']}" if r.get('anomaly') else ""))
    return 0


def cmd_decode(argv):
    ap = argparse.ArgumentParser(prog="owsi decode")
    ap.add_argument("op")
    ap.add_argument("data")
    a = ap.parse_args(argv)
    from .analysis import decode
    print(decode(a.op, a.data))
    return 0


def cmd_analyze_jwt(argv):
    ap = argparse.ArgumentParser(prog="owsi analyze-jwt")
    ap.add_argument("token")
    a = ap.parse_args(argv)
    from .analysis import analyze_jwt
    print(json.dumps(analyze_jwt(a.token), indent=2))
    return 0


def cmd_ca_hint(argv):
    app = Application(default_data_dir())
    print(f"""CA: {app.ca.ca_cert_path}
Chrome/Edge: Settings → Privacy → Security → Certificates → Manage
  → Authorities → Import → select owsi-ca-cert.pem → trust for websites.
macOS:  sudo security add-trusted-cert -d -r trustRoot \\
          -k /Library/Keychains/System.keychain owsi-ca-cert.pem
Linux:  cp owsi-ca-cert.pem /usr/local/share/ca-certificates/ && update-ca-certificates
Firefox: about:preferences#privacy → Certificates → Import…""")
    return 0


COMMANDS = {
    "serve": cmd_serve, "status": cmd_status, "report": cmd_report,
    "repeater": cmd_repeater, "fuzz": cmd_fuzz, "decode": cmd_decode,
    "analyze-jwt": cmd_analyze_jwt, "ca": cmd_ca_hint,
}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    fn = COMMANDS.get(cmd)
    if not fn:
        print(f"unknown command '{cmd}'\n{__doc__}")
        return 2
    try:
        return fn(rest) or 0
    except PermissionError as e:
        print(f"POLICY BLOCK: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
