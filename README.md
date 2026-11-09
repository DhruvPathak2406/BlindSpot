# BlindSpot

Adaptive network reconnaissance under partial observability: a synthetic network
generator, a noisy observation model, and a budgeted discovery engine. The
dashboard uses plain HTML, CSS, and JavaScript with a small Python standard-library
server. It is a simulator and does not probe real networks.

For the original project vision and planned architecture, see
[Project vision](docs/project-vision.md).

## Setup

```
pip install -r requirements.txt
```

## Launch the dashboard

From the project root (`Projects/`), run:

```powershell
python app/dashboard.py
```

Open http://127.0.0.1:8000. Set a seed, network size, action budget, and strategy,
then click **Generate network**. Use **Run steps**, **Run to completion**, or
**Explore subnet**. The dashboard shows discovered hosts/services, confirmed
links, action history, and remaining budget. Stop the local server with Ctrl+C.

The server binds to loopback (`127.0.0.1`) and only serves the synthetic simulator;
it has no real-network scanning functionality.

## Tests

```powershell
python -m pytest
```
