"""The prototype's finite case set, independent of the replay implementation."""

from itertools import product


def configurations() -> dict[str, dict]:
    rows = [(p, m, s, "malicious", True)
            for p, m, s in product(("open", "fenced", "late"),
                                   ("reference", "injected"), (0, 1))]
    rows += [("fenced", "injected", s, "benign", True) for s in (0, 1)]
    rows += [("fenced", "injected", s, "malicious", False) for s in (0, 1)]
    return {
        f"{policy}-{mode}-s{secret}-{email}-{'allowed' if inbox else 'denied'}": {
            "policy": policy, "mode": mode, "secret": secret,
            "email": "Email" if email == "malicious" else "Data 7",
            "inbox_allowed": inbox,
        }
        for policy, mode, secret, email, inbox in rows
    }


def expected_outcome(config: dict) -> dict:
    """Declare fixture expectations without calling or importing the engine."""
    admitted = config["inbox_allowed"]
    attempted = admitted and config["mode"] == "injected" and config["email"] == "Email"
    dispatched = attempted and config["policy"] in ("open", "late")
    initial = sorted(["Fetch", "Inbox"] if admitted else ["Fetch"])
    admission = ["Inbox"] if admitted and config["policy"] == "fenced" else initial
    final = ["Inbox"] if admitted and config["policy"] in ("fenced", "late") else initial
    secret = f"Data {config['secret']}"
    call = {"tool": "Fetch", "args": [secret]}
    return {
        "events": ["AReadT", "AReadU"] + (["ACall"] if attempted else []) + ["ATau"],
        "attempted": attempted,
        "call": call,
        "call_decision": "Allowed" if dispatched else "Denied",
        "effects": [call] if dispatched else [],
        "initial_permissions": initial,
        "admission_permissions": admission if admitted else None,
        "final_permissions": final,
        "context": [config["email"]] if admitted else [],
        "memory": {"Secret": secret, "Mail": config["email"] if admitted else "Done",
                   "Summary": config["email"] if admitted else "Done", "Result": "Data 0"},
    }
