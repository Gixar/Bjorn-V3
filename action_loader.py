# action_loader.py
# The one place actions.json becomes live action objects.
#
# There used to be two. orchestrator.py and utils.py each carried its own copy of
# load_actions / load_scanner / load_nmap_vuln_scanner / load_action, and the copies drifted —
# every fix landed in the orchestrator's, none in the web UI's:
#
#   * `None == 0` is False, so a portless action (actions/IDLE.py declares b_port = None) was
#     filed under the *host* actions on the web side, to be called with an ip and a port it never
#     had. That reached users as a 500 from the manual-attack dropdown, and was absorbed
#     downstream by a second port check in serve_netkb_data_json rather than fixed at the source.
#   * The guard refusing to register a stub with no execute() never crossed over.
#   * Neither did b_needs_internet, so an action loaded by the web UI could not be told apart
#     from one the orchestrator skips while offline.
#
# Three fixes, one copy each time. The classification lives here now, and
# test_standalone_actions.py fails if either module starts building actions itself again.
import json
import importlib
from typing import Any, List, NamedTuple, Optional


class LoadedActions(NamedTuple):
    """One read of actions.json.

    `actions` are host actions, called with (ip, port, row, action_key). `standalone` are the
    portless ones, called with no target at all — the split is what makes that safe. The two
    scanners are singletons the orchestrator holds by name rather than work items in a queue.
    """
    actions: List[Any]
    standalone: List[Any]
    network_scanner: Optional[Any]
    nmap_vuln_scanner: Optional[Any]


def load_actions(shared_data, logger, entries=None):
    """Build every action actions.json names, classified. `entries` overrides the file (tests).

    A module missing the attributes the b_* contract requires is logged and skipped rather than
    raised: one broken action must not take the whole set down with it. An ImportError still
    propagates — a module that cannot be imported at all is a broken install, and silently
    running without an attack module is the failure mode this codebase keeps having to hunt.
    """
    if entries is None:
        with open(shared_data.actions_file, 'r') as file:
            entries = json.load(file)

    actions, standalone = [], []
    network_scanner = nmap_vuln_scanner = None

    for entry in entries:
        module_name = entry["b_module"]
        module = importlib.import_module(f'actions.{module_name}')
        try:
            b_class = entry["b_class"]
            instance = getattr(module, b_class)(shared_data)
        except AttributeError as e:
            logger.error(f"Module {module_name} is missing required attributes: {e}")
            continue

        if module_name == 'scanning':
            network_scanner = instance
            continue
        if module_name == 'nmap_vuln_scanner':
            nmap_vuln_scanner = instance
            continue

        # An action the orchestrator cannot call has no business in the work queue.
        # actions/IDLE.py is a stub with no execute(): registered anyway, it was scored by the
        # planner as "never tried" on every host and then raised AttributeError every cycle —
        # 7 errors and 7 failed netkb marks in a 10-minute run, for something that is not a real
        # action. Checked at load, so any future stub is simply never registered rather than
        # failing once per host per cycle.
        if not callable(getattr(instance, "execute", None)):
            logger.info(f"Skipping {b_class}: no execute() — not a runnable action.")
            continue

        instance.action_name = b_class
        instance.port = entry.get("b_port")
        instance.b_parent_action = entry.get("b_parent")
        # Module-level opt-in flag (part of the b_* contract): actions that call out to the
        # internet are skipped while offline instead of failing once per cycle.
        instance.needs_internet = getattr(module, "b_needs_internet", False)
        # None means portless, not "some port" — the bug that only ever got fixed on one side.
        (standalone if instance.port in (0, None) else actions).append(instance)

    return LoadedActions(actions, standalone, network_scanner, nmap_vuln_scanner)
