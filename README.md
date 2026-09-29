<div align="center">
	<h1><img src="public/project-logo.jpeg" alt="Sanchar Saṅgaṇaka" width="720" /></h1>
  <p><strong>AI-based threat detection for unidirectional IP traffic</strong></p>
	<p><img src="public/favicon.png" alt="HarTimeError team logo" width="36" height="36" /> SIH26145 · Team HarTimeError</p>
</div>

Sanchar Saṅgaṇaka is a network-threat detection prototype that inspects traffic
after it crosses a software-emulated data diode. It extracts forward-only
features, combines known-attack classification with anomaly and protocol
detectors, and streams scored events to a live operator console.

## How it works

```text
PCAP replay or live traffic
	↓
One-way UDP relay and capture
	↓
Forward-only feature extraction
	↓
XGBoost classifier + LSTM autoencoder + detectors
	↓
Threat-score fusion → FastAPI and WebSocket → operator console
```

The console is built with TanStack Start, React, TypeScript, Tailwind CSS, and
Recharts. It shows live traffic and alerts, threat analysis, network trends,
model status, and system health. The UI reads backend responses; unavailable
values are shown as unavailable rather than fabricated.

## Requirements

- Linux for the network-namespace data-diode and packet-replay workflow
- Python 3 and `venv`/`pip`
- Node.js 20 or newer and npm
- `sudo` for the one-time network-tool setup and diode operations

> [!IMPORTANT]
> **No dataset download is needed to run the pre-trained demo.** Extract the
> bundled `models.tar.gz` archive as shown below, then start the app. Download
> datasets only to reproduce PCAP replay, feature extraction, or model training.

The full pipeline needs approximately 50 GB for datasets, plus space for
captures and generated features.

## Quick start

From a clone of the frontend branch:

```bash
git clone https://github.com/harshil-sri/SIH-2026.git
cd SIH-2026
bash scripts/setup_venv.sh
npm ci
tar -xzf models.tar.gz
make serve-dev
```

Open <http://127.0.0.1:8080>. The API listens on <http://127.0.0.1:8200>.
Model files under `models/artifacts/` are git-ignored; `models.tar.gz` contains
the bundled inference artifacts and restores them for a fresh checkout.

To send sample windows to the running console, use a second terminal:

```bash
make drive
```

Stop the API and console with `make stop`.

### Run frontend and API separately

Start the API and frontend together with `make serve-dev`, or start only the
frontend with:

```bash
npm run dev
```

The frontend expects the API at `http://127.0.0.1:8200` by default. Set
`VITE_API_BASE_URL` in `.env` to use another API URL; `.env.example` shows the
local default. For a local production build, run `make frontend-build`.

## Console routes

| Route       | View                               |
| ----------- | ---------------------------------- |
| `/`         | Overview and pipeline status       |
| `/events`   | Live traffic and alerts            |
| `/analysis` | Threat detection analysis          |
| `/network`  | Traffic analytics                  |
| `/models`   | Detection model status and metrics |
| `/system`   | API and system health              |
| `/about`    | Project information                |

## API

The FastAPI service is implemented in `serving/app.py`.

| Method      | Path                                                | Purpose                             |
| ----------- | --------------------------------------------------- | ----------------------------------- |
| `GET`       | `/health`, `/stats`, `/trend`, `/coverage`, `/meta` | Health and detection telemetry      |
| `GET`       | `/recent_alerts`                                    | Recent scored events                |
| `POST`      | `/score`, `/score_batch`                            | Score one or more feature windows   |
| `POST`      | `/demo/run`, `/demo/reset`                          | Run or reset synthetic demo traffic |
| `WebSocket` | `/ws/alerts`                                        | Stream scored events to the console |

## Full data pipeline

Dataset acquisition and replay are optional for running the console. They are
required for reproducing the PCAP-based pipeline.

```bash
# Optional, one-time: install packet tools and scoped sudo permissions
sudo bash scripts/bootstrap_sudo.sh

# Download raw PCAPs and labels (approximately 50 GB)
bash scripts/download_datasets.sh

# Build windows, replay traffic, extract features, train, and report
make windows
make slices
make replay
make extract
make train
make report
```

`make all` runs the pipeline sequence in one command. The packet tools and
network namespaces require Linux; the bootstrap script installs a scoped sudo
rule for the required networking commands. Review that script before running it
with `sudo`.

Generated datasets and intermediate outputs live under `datasets/` and `data/`
and are not tracked by Git. Attack-window timing and verification notes are in
[`docs/ATTACK_WINDOWS.md`](docs/ATTACK_WINDOWS.md).

## Development checks

```bash
npm run lint
npm run build
.venv/bin/python scripts/test_detectors.py
```

The detector regression script does not require `sudo` or network namespaces.

## Deployment

Deployment configuration is provided for the API on Render (`render.yaml`) and
the console on Vercel (`vercel.json`). Configure `VITE_API_BASE_URL` in the
frontend deployment to point to the deployed API. The API currently allows
cross-origin requests from any origin; restrict CORS before exposing it to
untrusted clients.

## Project layout

| Path                               | Contents                                           |
| ---------------------------------- | -------------------------------------------------- |
| `src/`                             | TanStack Start console, routes, and shared UI      |
| `serving/`                         | FastAPI inference service and live pipeline        |
| `detectors/`, `fusion/`            | Traffic detectors and score fusion                 |
| `diode/`, `replay/`, `extraction/` | One-way relay, PCAP replay, and feature extraction |
| `models/`                          | Training code and model-artifact directory         |
| `attacks/`, `scripts/`             | Attack generators and development/demo tooling     |
| `evaluation/`                      | Evaluation report and latency tools                |

## Team

**HarTimeError**

<table border="1" cellpadding="8" cellspacing="0">
	<thead>
		<tr>
			<th>Name</th>
			<th>GitHub profile</th>
		</tr>
	</thead>
	<tbody>
		<tr>
			<td>Harshil Srivastav</td>
			<td><a href="https://github.com/harshil-sri"><img src="https://img.shields.io/badge/GitHub-Profile-24292e?style=flat-square&amp;logo=github&amp;logoColor=white" alt="GitHub profile" /></a></td>
		</tr>
		<tr>
			<td>Kartik Arora</td>
			<td><a href="https://github.com/KA-1205"><img src="https://img.shields.io/badge/GitHub-Profile-24292e?style=flat-square&amp;logo=github&amp;logoColor=white" alt="GitHub profile" /></a></td>
		</tr>
		<tr>
			<td>Naman Goel</td>
			<td><a href="https://github.com/Naman-Goel-07"><img src="https://img.shields.io/badge/GitHub-Profile-24292e?style=flat-square&amp;logo=github&amp;logoColor=white" alt="GitHub profile" /></a></td>
		</tr>
		<tr>
			<td>Rhythm Arora</td>
			<td><a href="https://github.com/rhythmarora070"><img src="https://img.shields.io/badge/GitHub-Profile-24292e?style=flat-square&amp;logo=github&amp;logoColor=white" alt="GitHub profile" /></a></td>
		</tr>
		<tr>
			<td>Sagar Sukhija</td>
			<td><a href="https://github.com/sagarsukhijacodes"><img src="https://img.shields.io/badge/GitHub-Profile-24292e?style=flat-square&amp;logo=github&amp;logoColor=white" alt="GitHub profile" /></a></td>
		</tr>
		<tr>
			<td>Yuv Jindal</td>
			<td><a href="https://github.com/mr-yuvie"><img src="https://img.shields.io/badge/GitHub-Profile-24292e?style=flat-square&amp;logo=github&amp;logoColor=white" alt="GitHub profile" /></a></td>
		</tr>
	</tbody>
</table>
