# BlindSpot
### Adaptive Network Reconnaissance Under Partial Observability

**BlindSpot** is an intelligent network reconnaissance platform designed to address a fundamental limitation of traditional network scanning: incomplete visibility.

Traditional reconnaissance tools such as Nmap provide valuable information about discovered hosts, open ports, and running services. However, real-world networks are rarely fully observable. Firewalls, filtered ports, dynamic infrastructure, network segmentation, and scanning constraints can leave significant portions of a network undiscovered.

BlindSpot explores a different approach.

Instead of simply scanning a network and reporting what it finds, BlindSpot aims to maintain a probabilistic representation of the network, reason about what remains unknown, and intelligently determine which reconnaissance action should be performed next.

The ultimate objective is to maximise network visibility while operating under limited reconnaissance budgets.

> **Core Research Question:** Can an adaptive reconnaissance system discover network assets and infer network structure more efficiently than conventional fixed-scan and rule-based approaches when operating under partial observability?

---



## System Architecture

The proposed architecture consists of the following major components:

1. **Reconnaissance Engine** – Collects network observations through simulated discovery and authorised Nmap scan imports.
2. **Network Representation Engine** – Converts observations into a graph representation using NetworkX.
3. **Belief Engine** – Maintains probabilistic beliefs about network assets and relationships.
4. **Uncertainty Estimator** – Quantifies uncertainty associated with unknown hosts, services, and connections.
5. **Decision Engine** – Determines which reconnaissance action is likely to provide the greatest information gain.
6. **Learning Engine** – Experiments with machine learning and reinforcement learning to improve action selection.
7. **Evaluation Engine** – Compares adaptive strategies against baseline reconnaissance methods.
8. **Visualisation Dashboard** – Displays discovered assets, network topology, uncertainty, reconnaissance history, and performance metrics.

### High-Level Workflow

```text
Network / Synthetic Environment
             |
             v
    Reconnaissance Engine
             |
             v
   Observation Processing
             |
             v
      Network Graph
             |
             v
       Belief Engine
             |
             v
  Uncertainty Estimation
             |
             v
     Decision Engine
             |
             v
  Next Reconnaissance Action
             |
             v
     New Observation
             |
             +----------> Update Belief Graph
                              |
                              v
                         Evaluation
                              |
                              v
                         Dashboard
```



Potential future research directions include:

- Generalisation across heterogeneous network environments.
- Improved probabilistic modelling of hidden network structures.
- More efficient reconnaissance under strict action budgets.
- Multi-agent reconnaissance.
- Continual learning in changing network environments.
- Robustness against noisy, incomplete, and misleading observations.
- Evaluation on larger and more complex network topologies.

---

#
**BlindSpot — Discovering What Traditional Reconnaissance Leaves Behind.**
