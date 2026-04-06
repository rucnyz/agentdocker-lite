"""Image management: containers/storage, config cache, layer extraction."""

from nitrobox.image.store import get_image_config, ImageConfig
from nitrobox.image.layers import (
    prepare_rootfs_layers_from_docker,
    rmtree_mapped,
)

__all__ = [
    "get_image_config",
    "ImageConfig",
    "prepare_rootfs_layers_from_docker",
    "rmtree_mapped",
]
