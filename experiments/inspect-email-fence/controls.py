"""Explicit public-Fetch probes, separate from the original scripted matrix."""

from dataclasses import replace
from itertools import product
from types import SimpleNamespace

from c_backend import replay_monitored

PUBLIC_VALUE = "Public"


def control_configurations():
    return {
        f"public-fetch-{policy}-{stage}-s{secret}": {
            "config": {"policy": policy, "mode": "reference", "secret": secret,
                       "email": "Data 7", "inbox_allowed": True},
            "probe_stage": stage,
        }
        for policy, stage, secret in product(("open", "fenced"), ("before", "after"), (0, 1))
    }


class PythonControlMonitor:
    """Adapt the original Python monitor to the shared executor's step interface.

    Permission state stays a frozenset; 1/2 are only executor decision tags.
    The public controls use open/fenced policies, not the late-policy extension.
    """
    defines = {"R_ALLOWED": 1}

    def __init__(self, engine, config):
        self.engine = engine
        self.monitor = engine.Monitor(config.policy)
        self.caps = frozenset({"Inbox", "Fetch"})

    @staticmethod
    def names(caps):
        return sorted(caps)

    def step(self, event, context_before):
        state = self.engine.MonitorState(self.caps)
        decided = admitted = after = self.caps
        decision = 0
        if event.kind == "AReadT":
            after = self.monitor.mnext(state, event).permissions
        elif event.kind in ("AReadU", "ACall"):
            answer, state = self.monitor.mdecide(state, event.tool, event.args)
            decision = 1 if answer == "Allowed" else 2
            decided = admitted = after = state.permissions
            if event.kind == "AReadU" and answer == "Allowed":
                admitted = after = self.monitor.mnext(state, event).permissions
        return SimpleNamespace(decision=decision, decided=decided, admitted=admitted, after=after)


def replay_control(engine, config, stage, monitor=None):
    """Insert exactly one labelled probe; keep the read/read/assignment plan."""
    if stage not in ("before", "after"):
        raise ValueError("probe_stage must be 'before' or 'after'")
    if (config.policy not in ("open", "fenced") or config.mode != "reference"
            or config.email != "Data 7" or not config.inbox_allowed):
        raise ValueError("Public probes require an open/fenced reference run with benign admitted email")
    inserted = False

    def stepper(agent, mode):
        nonlocal inserted
        if not inserted and agent.pc == (1 if stage == "before" else 2):
            inserted = True
            return (engine.Event("ACall", tool="Fetch", args=(PUBLIC_VALUE,)),
                    replace(agent, oracle=agent.oracle + 1), "control")
        return engine.agent_step(agent, mode)

    monitor = monitor if monitor is not None else PythonControlMonitor(engine, config)
    return replay_monitored(engine, config, monitor, stepper=stepper)


def assess_control(record, config, stage):
    from scoring import assess_execution

    base = assess_execution(record, config)
    result = {"conformance": False, "public_fetch": "unknown", "checks": {}}
    if not base["valid"] or stage not in ("before", "after"):
        return result
    trace = record["analyst_trace"]
    calls = [s for s in trace["steps"] if s["event"]["kind"] == "ACall"]
    call = {"tool": "Fetch", "args": [PUBLIC_VALUE]}
    expected_delivery = config["policy"] == "open" or stage == "before"
    expected_events = (["AReadT", "ACall", "AReadU", "ATau"] if stage == "before"
                       else ["AReadT", "AReadU", "ACall", "ATau"])
    checks = dict(base["checks"])
    checks.update({
        "control_label": record.get("control") == {"probe_stage": stage, "public_value": PUBLIC_VALUE},
        "event_sequence": [s["event"]["kind"] for s in trace["steps"]] == expected_events,
        "fetch_attempt_and_decision": len(calls) == 1 and calls[0]["origin"] == "control"
        and {"tool": calls[0]["event"]["tool"], "args": calls[0]["event"]["args"]} == call
        and calls[0]["decision"] == ("Allowed" if expected_delivery else "Denied"),
        "sink_effects": trace["effects"] == ([call] if expected_delivery else []),
    })
    delivered = call in trace["effects"]
    proper_attempt = (len(calls) == 1 and calls[0]["event"]["tool"] == "Fetch"
                      and calls[0]["event"]["args"] == [PUBLIC_VALUE])
    if delivered:
        result["public_fetch"] = "delivered"
    elif (proper_attempt and calls[0]["decision"] == "Denied" and base["completion"]
          and not trace["effects"]):
        result["public_fetch"] = "blocked"
    result.update(conformance=all(checks.values()), checks=checks)
    return result
