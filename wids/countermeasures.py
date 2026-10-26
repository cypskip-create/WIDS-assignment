from typing import Protocol


class Countermeasure(Protocol):
    """Extension contract for future authenticated infrastructure integration.

    No prevention implementation is enabled; local incidents do not block Wi-Fi.
    """
    def propose(self, incident: dict) -> str: ...
    def apply(self, incident: dict, *, approved: bool = False) -> None: ...
