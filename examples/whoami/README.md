# ztlp-whoami

A tiny app that shows the identity a ZTLP gateway signed for each request: person, device, zone,
group, assurance, and whether the signature verifies. It exists to exercise the admin panel's
"Add service" flow end to end and to demo identity-aware access.

Standard library Python, one file. Tests: `python3 -m unittest test_app.py`.

## Run it behind a gateway from the admin panel
1. In the panel: Services, Add service. Name `whoami`, backend `127.0.0.1:8095`, tick
   "Sign people in with ZTLP", set the UDP port, save.
2. Copy `.env.example` to `.env` and paste the service's "App settings" block into it.
3. `docker compose up -d --build`
4. On the service page, show the gateway install script and run it as root on this box.
5. Grant access on the service page, then open `http://whoami.<zone>/` from an enrolled device.

`/who.json` returns the same data as JSON; `/up` is the health check.
