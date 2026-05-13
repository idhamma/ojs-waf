# Files and Folders That Are Not Needed in the Project Folder

This list is based on the active runtime path:

```text
integrations/waf_checker.lua
  -> core/sidecar_agent.py
  -> ml_training/train_waf_model.py
  -> ml_training/waf_model.pkl
```

## Safe Cleanup Candidates

These are generated files or local runtime artifacts. They are not source code
and should not be committed.

```text
__pycache__/
core/__pycache__/
ml_training/__pycache__/
sidecar.log
venv310/
integrations/docker/ojs-docker/.venv/
integrations/docker/ojs-docker/database/
integrations/docker/ojs-docker-new2/database/
integrations/docker/ojs-docker/ojs_files/scheduledTaskLogs/
integrations/docker/ojs-docker/ojs_files/usageStats/archive/
integrations/docker/ojs-docker/ojs_files/usageStats/stage/
integrations/docker/ojs-docker/ojs_files/usageStats/usageEventLogs/
```

Reason:

- Python cache files can always be regenerated.
- `sidecar.log` is runtime output.
- virtual environments are local machine state.
- Docker database folders are container volume state, not project source.
- OJS scheduled task logs and usage stats are runtime data.

## Tracked Files That Should Usually Be Removed From Git

These files are currently tracked by Git but are generated artifacts.

```text
core/__pycache__/blocking_mechanism.cpython-310.pyc
core/__pycache__/blocking_mechanism.cpython-314.pyc
ml_training/__pycache__/__init__.cpython-310.pyc
ml_training/__pycache__/train_rf_ddos_model.cpython-314.pyc
ml_training/__pycache__/train_waf_model.cpython-310.pyc
ml_training/__pycache__/train_waf_model.cpython-314.pyc
sidecar.log
```

Recommendation:

- remove them from Git tracking
- keep `__pycache__/`, `*.pyc`, and `*.log` ignored

## Stale or Broken Demo Files

These files are not part of the active OpenResty-to-sidecar flow and currently
do not match the active TCP sidecar implementation.

```text
core/client_library.py
integrations/demo_app.py
integrations/nginx_integration.py
```

Reasons:

- `core/client_library.py` talks to `/tmp/waf-agent.sock` via Unix socket, but
  `core/sidecar_agent.py` listens on TCP `0.0.0.0:9999`.
- `integrations/demo_app.py` imports `others.client_library`, which is missing.
- `integrations/nginx_integration.py` also imports `others.client_library`,
  which is missing.

Keep them only if you plan to repair them as TCP-based examples.

## Legacy or Alternative Architecture Files

These files belong to an older eBPF/DDoS direction or an alternate feature
extractor path. They are not used by the current userspace OJS WAF runtime.

```text
core/waf_ml_features.py
ml_training/train_ddos_model.py
ml_training/train_rf_ddos_model.py
ml_training/dt_model_ebpf.json
ml_training/rf_model_ebpf.json
```

Reasons:

- the sidecar imports `extract_features` from `ml_training/train_waf_model.py`
- the DDoS trainers export eBPF-oriented JSON artifacts
- no active runtime file loads `dt_model_ebpf.json` or `rf_model_ebpf.json`
- `core/waf_ml_features.py` defines a different 20-feature extractor that is
  not used by the active sidecar

Keep these only if the thesis/project still includes an eBPF DDoS module.

## Duplicate or Old Dataset Files

These are likely historical snapshots. They are not needed for runtime.

```text
dataset/raw/old dataset eight may.csv
dataset/labeled/old dataset eight may.csv
```

The current runtime writes date-based files such as:

```text
dataset/raw/2026-05-08.csv
dataset/labeled/2026-05-08.csv
```

Keep old datasets only if they are required for thesis evidence or retraining.

## Schema Files To Consolidate

```text
dataset/meta/schema_v1.json
dataset/meta/schema_v2.json
dataset/meta/schema_v3.json
```

Only `schema_v3.json` is closest to the current sidecar writer. The older
schemas are useful as history, but not necessary for active operation.

Important: `schema_v3.json` still documents fields that the current sidecar does
not write, including response fields, TCP flags, `query_params_json`, `proto`,
and `pcap_file`.

## Docker/OJS Local State

The repository contains local Docker/OJS working folders under:

```text
integrations/docker/
```

This path is already ignored by `.gitignore`, but it is physically large in the
workspace. During inspection, the project folder was about 2.4 GB, with major
contributors including:

```text
venv310/                              about 1.9 GB
integrations/docker/ojs-docker/       about 351 MB
integrations/docker/ojs-docker/database/ about 201 MB
integrations/docker/ojs-docker-new2/  about 137 MB
```

Keep only reusable Docker source/config files. Database volumes, installed app
state, uploaded OJS files, and local virtual environments should be outside the
source project or ignored.

## Suggested `.gitignore` Additions

Current `.gitignore` is very small. Add these patterns:

```gitignore
*.pyc
*.pyo
*.log
__pycache__/
.venv/
venv/
venv310/

dataset/raw/*.csv
dataset/labeled/*.csv
!dataset/raw/.gitkeep
!dataset/labeled/.gitkeep

integrations/docker/
```

If model artifacts and generated datasets are part of the thesis submission,
keep them intentionally. Otherwise, store them outside Git or in a release
artifact folder.

