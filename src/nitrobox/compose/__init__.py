"""Docker Compose compatibility layer.

Public API:
    ComposeProject — orchestrate multi-service sandboxes from docker-compose.yml
    SharedNetwork  — Podman-style shared userns+netns between sandboxes
"""

from nitrobox.compose._network import SharedNetwork
from nitrobox.compose._project import ComposeProject

# Re-exported for internal use (tests, _project.py); not public API.
from nitrobox.compose._parse import (  # noqa: F401
    _Service, _parse_compose, _substitute, _topo_sort,
)

__all__ = [
    "ComposeProject",
    "SharedNetwork",
]
