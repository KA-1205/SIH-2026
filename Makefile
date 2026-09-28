# SIH26145 — build & demo targets
PY    = .venv/bin/python
SHELL := /bin/bash

.PHONY: help setup venv download diode windows slices replay extract train report \
        bench serve serve-dev stop dashboard demo-live all clean-data clean-derived \
        frontend-install frontend-build frontend-dev

help:             ## list targets
	@grep -hE '^[a-z-]+:.*?##' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-14s\033[0m %s\n",$$1,$$2}'

setup:            ## one-time: apt tooling + scoped sudoers (needs password once)
	sudo bash scripts/bootstrap_sudo.sh

venv:             ## python environment
	bash scripts/setup_venv.sh

download:         ## resumable dataset fetch (~50GB)
	bash scripts/download_datasets.sh

diode:            ## bring up the emulated diode and re-prove one-way-ness
	bash diode/setup_diode.sh && bash diode/verify_diode.sh

windows:          ## derive attack windows from the label CSVs (12h-clock + TZ corrected)
	$(PY) replay/build_windows.py

verify-windows:   ## optional: confirm windows against attacker bursts in the raw pcaps
	$(PY) replay/derive_windows_from_pcap.py

slices:           ## cut the densest sub-window per attack + benign slices
	$(PY) replay/make_slices.py

replay:           ## replay every slice through the diode, capture monitor-side
	$(PY) replay/run_plan.py

extract:          ## forward-only features for every captured slice
	$(PY) extraction/batch_extract.py

train:            ## both models
	$(PY) models/train_xgb.py && $(PY) models/lstm_ae.py

bench:            ## measure detector latency (run on an idle host)
	$(PY) evaluation/bench_latency.py

report:           ## assemble evaluation/REPORT.md from all artifacts
	$(PY) evaluation/make_report.py

serve:            ## start inference API :8200 + console (prod build if present, else dev)
	bash scripts/serve.sh start

serve-dev:        ## start inference API :8200 + console dev server :8080 (hot reload)
	bash scripts/serve.sh start dev

stop:             ## stop both servers
	bash scripts/serve.sh stop

dashboard:        ## console only (production build on :8401; run 'make frontend-build' first)
	bash scripts/serve.sh start prod

frontend-install: ## install console dependencies (npm)
	npm install

frontend-build:   ## build the console for local serving (.output/, node-server preset)
	NITRO_PRESET=node-server npm run build

frontend-dev:     ## console dev server only (:8080)
	npm run dev

drive:            ## push synthetic windows at the API to exercise the console
	$(PY) scripts/drive_demo.py

demo-live:        ## full live demo loop through the emulated diode
	bash scripts/live_demo.sh

all: windows slices replay extract train bench report  ## full pipeline from raw pcaps

clean-derived:    ## remove features + models, keep captures and slices
	rm -rf data/features models/artifacts/*

clean-data:       ## remove ALL derived artifacts, keep raw datasets
	rm -rf data/features data/captures replay/slices models/artifacts/*
