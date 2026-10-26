import platform
from pathlib import Path


def available_interfaces():
    """Only Linux interfaces already configured in monitor mode are offered."""
    if platform.system() != "Linux":
        return [], "Live raw 802.11 capture requires Linux and a compatible adapter already in monitor mode. Offline replay is available on this system."
    interfaces = []
    for path in Path("/sys/class/net").glob("*"):
        try:
            if (path/"type").read_text().strip() == "803":
                interfaces.append(path.name)
        except OSError:
            continue
    return interfaces, "No interface modes are changed. Capture requires permission and an authorized network." if interfaces else "No monitor-mode wireless interface found (Linux ARPHRD 803 required). Configure hardware separately with authorization."


def validate_interface(name):
    interfaces, explanation = available_interfaces()
    if name not in interfaces:
        raise ValueError(explanation)
