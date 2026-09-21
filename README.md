# AI Multi-Modal Phishing Defense Platform

A defense-oriented platform that judges a link or a message from several kinds of evidence (the
address, the page, the wording, threat lists) and turns that evidence into a risk score, a
recommended action, guided response steps, and a feedback loop for learning.

**This repository is v0.2.** It implements the parts below marked *built*. The rest is the research
target, listed honestly in the roadmap so no one mistakes the plan for the product.

```
message ─► text signals ─────────────────────────────┐
link ────► threat-list check (policy floor)           │
        └► Stage 1: address features ─ p1             │
              │ p1 ≤ t_low → allow (stop)             ├─► fusion ─► risk ─► recommended action
              │ p1 ≥ t_high → block (stop, page never opened)         │            + evidence
              ▼ otherwise                                             │            + guidance
        SSRF-guarded fetch ─► Stage 2: HTML/DOM features ─ p2 ────────┘            + incident / feedback
```

The research question the cascade is built to answer: **how much accuracy do you keep, and how much
latency and exposure do you save, by opening the page only when the address is uncertain?**
`t_low` and `t_high` are the experimental knob.

## What is built, and how far

| Capability | Status |
|---|---|
| Address (URL) analysis: 28 features, heuristic baseline, trained model, time-based split | built |
| Page (HTML/DOM) analysis: forms, brand imitation, hidden frames, scripts | built, **rule-based, not trained** |
| Cascade with measurable escalation rate and threshold sweep | built |
| Text/message analysis: wording, sender checks, link extraction, text-vs-link consistency | built, **rule-based, not trained** |
| Fusion of URL + page + text, with missing-modality handling | built; default weights are priors, learned fusion is fitted with `experiments/fit_fusion.py` |
| Calibration diagnostics (Brier, ECE, reliability bins) | built; the UI shows a probability only when the fusion was fitted |
| Threat intelligence | built as a policy layer + local blocklist provider; no live feed included |
| Evidence-based explanation | built (feature-level; not full XAI) |
| Prevention: allow / warn / block **advice**, unverified state | built; the web app cannot enforce (`enforcement: advisory`) |
| Response: guided steps, incident record for every block, indicators of compromise | built (advice and records; nothing is automated) |
| Learning: user feedback stored, exported for human review | built |
| SSRF-guarded fetching | built, DNS-rebinding gap documented |
| Screenshot / visual analysis | **not built** |
| Trained text model, trained page model | **not built** (needs data) |
| Real results on real phishing data | **not yet** |
| Async job queue, isolated fetch worker, PostgreSQL, Redis, users/auth, browser extension | **not built** |

### Why the "not built" items are not built

* **Visual analysis** means running a browser against attacker sites. That should not exist before the
  isolated fetch worker does, and it needs a brand reference corpus and labelled screenshots to mean anything.
* **Trained page/text models** need the paired dataset this repo's collector is designed to produce.
  Training on the synthetic data would only produce meaningless numbers.
* **Queue, isolated worker, PostgreSQL, Redis, auth** cannot be verified in a single-process development
  environment, and SQLite plus an in-memory limiter are fine until you run several workers. Deploy the fetcher
  in a network-restricted container first; that is the single most valuable hardening step.
* **Browser extension** is the layer that would turn `recommended_action` into real enforcement, and it needs
  testing in a real browser. It should call `POST /api/analyze` unchanged.

## Roadmap

| Version | Adds | State |
|---|---|---|
| 0.1 | URL + HTML cascade, evaluation harness | done |
| 0.2 | Text modality, message analysis, learned fusion, calibration, threat-intel seam, response and feedback | **this release** |
| 0.3 | Real dataset, trained URL and page models, first real evaluation | next, needs your data |
| 0.4 | Screenshot modality in an isolated fetch worker | after 0.3 shows where URL+HTML fails |
| 0.5 | Live threat-intel providers, evaluated only on post-snapshot URLs | |
| 0.6 | Async jobs, PostgreSQL, Redis, auth | before a public deployment with several workers |
| 0.7 | Browser extension (enforcement) | |
| 1.0 | Production deployment and full experiment set | |

Each step must produce a number in the experiment table below, or it does not earn its place.

Target experiment (same held-out test set for every row): rule-based, URL only, page only, text only,
URL+page, URL+page+text, +visual, +threat intel; measured by PR-AUC, TPR at low FPR, precision, recall,
latency, escalation rate, calibration, and behaviour with a missing modality.

## The result object

`POST /api/analyze` and `POST /api/analyze-message` return the same shape. These four are kept apart
on purpose:

| Field | Meaning |
|---|---|
| `probability`, `calibrated` | model output; `calibrated` is true only when a fitted fusion produced it |
| `risk` | probability as 0-100, for display (the UI calls it "fishiness") |
| `label`, `verified` | `safe` / `suspicious` / `phishing` / `unverified`. **Unverified means the page was needed but could not be opened; it is never reported as safe** |
| `recommended_action`, `enforcement` | `allow` / `warn` / `block`, and who enforces it (`advisory` here) |

Also returned: `modalities` (status and score per modality, including `visual: not_implemented`), `stages`,
ranked `evidence`, `links` (for messages), `guidance`, `indicators`, and `versions` so any number in the paper
traces back to exact models.

## Layout

| Path | What it is |
|---|---|
| `engine/` | Detection logic, no web framework: `urlfeatures`, `urlmodel`, `pagefeatures`, `textfeatures`, `fusion`, `threatintel`, `response`, `fetcher`, `cascade` |
| `app/` | FastAPI layer, SQLite store, rate limiter, static frontend |
| `ml/` | `train_url_model.py` (time-based split), `calibration.py` |
| `experiments/` | `fit_fusion.py`, `evaluate.py` (ablations, sweep, calibration) |
| `scripts/` | `collect_dataset.py`, `export_feedback.py`, `make_synthetic_smoke_data.py` (**never report results from it**) |
| `tests/` | `python -m unittest discover -s tests -t .` |

## Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload          # http://127.0.0.1:8000
```

Without a trained model it uses `heuristic-v1`, a transparent hand-weighted baseline that a trained model
must beat. Upgrading from v0.1: delete `data/app.db` (the schema changed).

## Research workflow

```bash
# 1. Collect paired data (isolated VM). Feeds are yours to choose; check their terms.
python -m scripts.collect_dataset --phish feeds/phish.txt --benign feeds/tranco.csv \
    --n-phish 1000 --n-benign 500 --out data/paired.jsonl --csv-out data/urls.csv

# 2. Train Stage 1 on the URL list (splits by time, records the boundary in the bundle)
python -m ml.train_url_model --csv data/urls.csv --out models/url_v1.joblib --version url-gbm-v1

# 3. Fit fusion on the OLDER half of the held-out rows (never on training rows, never on the test half)
python -m experiments.fit_fusion --data data/paired.jsonl --url-model models/url_v1.joblib --out models/fusion_v1.json

# 4. Evaluate on the untouched NEWER half, with the threshold sweep and calibration
python -m experiments.evaluate --data data/paired.jsonl --url-model models/url_v1.joblib \
    --fusion models/fusion_v1.json --sweep

# 5. Serve
PHISHDEF_URL_MODEL=models/url_v1.joblib PHISHDEF_FUSION=models/fusion_v1.json uvicorn app.main:app
```

Data roles: rows before the URL model's boundary **train** it; the older half of the rest **validates**
(fits fusion); the newer half **tests**. A fusion file records which URL model it was fitted for and the
app refuses to load a mismatch.

Pitfalls that would invalidate the paper if ignored:

* **Login-page bias.** If benign samples are homepages and phishing samples are login pages, the page stage
  learns "password field = phishing". The collector fetches `/` and `/login` for every benign domain. Check the
  class balance of `collects_credentials`.
* **Time leakage.** Campaigns produce near-duplicate URLs; random splits leak them. Split by time (done).
* **Dead pages.** Phishing pages vanish within hours; capture HTML at collection time (done).
* **Accuracy is the wrong headline.** Real phishing is rare. Report PR-AUC, TPR at low FPR, precision.
* **Threat-intel circularity.** Feeds are often your label source. Threat intel is therefore a policy layer
  here, and `evaluate.py` never touches it. To measure what it adds, evaluate only on URLs first seen after the
  list snapshot.
* **Calibration.** A learned fusion is calibrated for the validation slice's phishing share. Real traffic is
  usually far less phishy; say so before calling any score a probability.
* **Text model.** The text stage is untrained. Do not describe it as NLP or ML in the paper until you train
  and evaluate one on a labelled message corpus and compare it with this baseline.

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/analyze` `{"url", "mode": "cascade" or "full"}` | Analyse a link. `full` always inspects the page (for experiments) |
| `POST /api/analyze-message` `{"text", "sender"?, "subject"?, "mode"?}` | Analyse a pasted email/SMS and up to three links in it. Message text is never stored |
| `POST /api/feedback` `{"analysis_id", "verdict": "phishing" or "legitimate"}` | User vote, at most 3 per check |
| `GET /api/health` | Model versions and which modalities are live |
| `GET /api/stats`, `/api/history`, `/api/incidents`, `/api/feedback/export` | **Admin only** |

Admin endpoints return 404 unless `PHISHDEF_ADMIN_TOKEN` is set, and then require it as `X-Admin-Token`.

Configuration (environment): `PHISHDEF_URL_MODEL`, `PHISHDEF_FUSION`, `PHISHDEF_TI_LIST` (a text file of
domains/URLs), `PHISHDEF_DB`, `PHISHDEF_T_LOW`, `PHISHDEF_T_HIGH`, `PHISHDEF_RATE_PER_MIN`,
`PHISHDEF_RATE_BURST`, `PHISHDEF_TRUST_PROXY` (1 only behind a proxy you control), `PHISHDEF_STORE_URLS`
(0 keeps only host names), `PHISHDEF_ADMIN_TOKEN`.

## The defense lifecycle

| Stage | What happens here | What is deliberately not claimed |
|---|---|---|
| Detect / assess | cascade, text, fusion, evidence | |
| Prevent | allow / warn / block advice, unverified state | The web app cannot block anything; an extension or gateway must enforce |
| Respond | incident record for every block; indicators (domain, URL, form-action domain, sender domain); guided steps | No automatic takedown or reporting |
| Recover | "Already tapped it?" checklist: reset passwords, revoke sessions, MFA, call the bank | The app cannot reset or revoke anything itself |
| Learn | user feedback stored; `scripts/export_feedback.py` exports disagreements for **human review** | Votes are untrusted and a poisoning vector. They never flow into training automatically |

## The UI

A playful pond theme: the person is the fish, the link is the bait. The fish reacts to the verdict. Verdict
copy is in `app/static/app.js` (`VERDICT`); colours are the CSS variables at the top of `app/static/style.css`.
Fonts load from Google Fonts. The score is labelled "fishiness"; a percentage appears only for calibrated results.

## Security notes

* The fetcher (`engine/fetcher.py`) is the riskiest code here. It blocks non-public addresses, re-validates every
  redirect, caps size/time/redirects and never runs JavaScript. DNS rebinding is not fully closed: deploy it in a
  container whose network policy blocks your internal ranges, with no database credentials.
* Only load model files you trained: joblib files are pickles.
* All frontend rendering uses `textContent` because URLs, page text and message wording are attacker-controlled.
  The app sends a strict CSP and API docs are disabled.
* Submitted links can contain personal data. Decide a retention policy before publishing a link in a paper.
* The rate limiter is in-memory and per-process (message checks cost 3 tokens). Use Redis with several workers.

## Status: what has and hasn't been verified

Verified in development: 86 unit tests pass (URL and page analysis, text analysis, message cascade, threat-intel
policy, fusion fitting and the fit/test split, calibration plumbing, incidents and feedback, SSRF guard against a
local test server including redirect-to-metadata-address, training, evaluation, store, rate limiter); the frontend
was driven in headless Chromium at desktop and phone widths (both tabs, keyboard tab switching, feedback); the API
handlers ran end to end against stand-ins for FastAPI.

**Not verified:** how the frontend looks with its real fonts (my preview had no internet), running under real
FastAPI/uvicorn, the Docker build, live fetching of real websites, and anything on real phishing data. Expect small
fixes on first run. Heuristic weights, fusion priors and the default thresholds are priors, not fitted values.
