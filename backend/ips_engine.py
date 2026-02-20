from backend.logger import log_event

# Memory of blocked attack types (simple prevention memory)
_blocked_patterns = set()


def process_attack(attack_type):
    """
    attack_type: string (DoS, Probe, R2L, U2R, Normal)
    Returns: action ("ALLOWED" or "BLOCKED")
    """

    # If Normal → allow
    if attack_type.lower() == "normal":
        log_event(attack_type, "ALLOWED")
        return "ALLOWED"

    # If already blocked before → keep blocking
    if attack_type in _blocked_patterns:
        log_event(attack_type, "BLOCKED")
        return "BLOCKED"

    # First time attack detected → block and remember
    _blocked_patterns.add(attack_type)
    log_event(attack_type, "BLOCKED")
    return "BLOCKED"
