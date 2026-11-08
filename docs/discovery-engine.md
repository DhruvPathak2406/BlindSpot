# Discovery engine

The discovery engine communicates with the simulator only through
`ObservationModel.scope()` and `ObservationModel.execute()`. It stores agent-side
evidence in immutable `DiscoveryState` snapshots and chronological
`ActionRecord` entries.

Each completed `ReconAction` consumes one budget unit. A `PORT_SCAN` without a
specific port probes the configured top-port list, so its cost is still one
action. Invalid actions do not consume budget or enter history. A host that
does not respond is recorded as checked, not as confirmed absent.

Example from the repository root (set `PYTHONPATH=src`; in PowerShell, use
`$env:PYTHONPATH = "src"`):

```python
from blindspot.core.config import GeneratorConfig, ObservationConfig
from blindspot.discovery.discovery_engine import DiscoveryEngine, FixedOrderStrategy
from blindspot.simulator.network_generator import generate_network
from blindspot.simulator.observation_model import ObservationModel

topology = generate_network(GeneratorConfig(seed=42))
model = ObservationModel(topology, ObservationConfig(), seed=42)
engine = DiscoveryEngine(model, budget=100)
records = engine.run(FixedOrderStrategy(), max_actions=20)
print(len(engine.state.discovered_hosts), engine.budget_remaining)
```

`RandomDiscoveryStrategy(seed=...)` selects among eligible host-discovery,
port-scan, and service-identification actions. Both strategies stop when no
eligible action remains; `run()` also stops at the remaining budget or the
optional `max_actions` limit. The current budget unit is a completed action,
not an individual address or port probe.
