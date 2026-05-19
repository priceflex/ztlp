# Hermes Session Handoff — ZTLP Launch App to AWS Prod

## 1. Project Goal
Deploy the `ztlp.net` Launch app to the production test AWS Nameserver (`34.219.38.89`) using Docker, and expose it via ngrok so Steve can use the referral code flow. Provide production-grade readiness instead of running it locally.
**Success:** The `ztlp.net` public launcher is reachable over the internet via an ngrok tunnel.

---

## 2. What Was Done This Session

### 1. Repository Migration & Deployment
- Copied `~/ztlp/ztlp.net` to the AWS Nameserver (`34.219.38.89`) via `rsync`.
- Created production `.env` config.
  - `LAUNCH_BIND_HOST=0.0.0.0`
  - `LAUNCH_REQUIRE_POW=0`
  - `LAUNCH_PUBLIC_HOST=kathyrn-fraternal-alayah.ngrok-free.dev`
- Built and started the `ztlp-launch` Python WSGI app container via `docker compose up -d`.

### 2. Networking (ngrok)
- Deployed `ngrok` container (`ngrok/ngrok`) attached to `--network host` to forward traffic securely to localhost:8080.
- Resolved address binding conflict (`listen tcp 0.0.0.0:4040`) by reusing local host ports and correctly pointing ngrok to HTTP 8080.
- Verified ngrok tunnel is healthy and serving HTTP 200 responses to public requests for the `ztlp.net` Launch app.

---

## 3. Active Tasks

### Task 1: Verify End-to-End Onboarding Flow
**Status:** In Progress
**Description:** Steve wants to test the ZTLP Launch onboarding flow using his referral code. The ngrok tunnel is live. We need to confirm the claim UI works, SQLite persists correctly, and the zone is properly processed.
**Next steps:** Test going to `https://kathyrn-fraternal-alayah.ngrok-free.dev/start` and using the referral code `ZTLP-E2E-2026`.
**Relevant files:** `ztlp.net/launch_app/app.py`, `ztlp.net/data/launch.sqlite3`

---

## 4. Technical Context

### Architecture
```
Public Internet (Steve) ──https──► ngrok tunnel ──http──► ztlp-launch container (0.0.0.0:8080)
                                    (AWS NS Host)
```

### Key Assets
- AWS Host: `34.219.38.89` (ssh `ubuntu@34.219.38.89` via `ztlp_test_key`)
- Launch App Path: `~/ztlp.net` (on AWS host)
- Ngrok URL: `https://kathyrn-fraternal-alayah.ngrok-free.dev`

### Containers Running
| Container | Description |
|-----------|-------------|
| `ztlp-launch` | Python 3.12 WSGI App, binds to `0.0.0.0:8080`. Restart policy: `unless-stopped`. |
| `ngrok-launch` | Hosts the ngrok edge tunnel routing to `8080`. |

---

## 5. Decisions Made

1. **Move launch app from local to AWS:** Running locally hit port binding and ngrok issues. Moving to the AWS Nameserver test host ensures it's reachable and running alongside the canonical NS.
2. **POW Disabled:** Explicitly disabled Proof-of-Work to simplify testing and to match the referral flow requirements (using `LAUNCH_REQUIRE_POW=0`).

---

## 6. Known Problems
- `LAUNCH_PORT` uses `8080`. If another container attempts to bind `8080` on the network host level, it will collide.
- Ngrok is running in a throwaway container without persistent credentials for the free static domain, meaning a container restart or recreation will result in a random URL change unless the URL is updated in the `.env` again.

---

## 7. Open Questions
1. Do we need to hook up email configuration immediately for onboarding flows?
2. Does the local AWS `ztlp-ns` container interact with this Launch app instance correctly to retrieve enrollment tokens?

---

## 8. Next Session Startup Plan
1. Send an HTTP request to `https://kathyrn-fraternal-alayah.ngrok-free.dev/health` to confirm the proxy works.
2. Read the SQLite DB: `ssh -i ~/ztlp/.ssh/ztlp_test_key ubuntu@34.219.38.89 'sqlite3 ~/ztlp.net/data/launch.sqlite3 "select * from onboarding_requests"'`
3. Ask Steve if he encountered any issues during the referral flow.

---

## 9. Git Workflow Status
Did not commit anything to Git because the main migration was an `rsync` of untracked files directly to the AWS box. Will review local `~/ztlp` untracked files and commit them if necessary on the next turn.