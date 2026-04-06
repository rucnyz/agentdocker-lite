"""Backward-compat shim — moved to nitrobox.image.{store,layers}."""

# ruff: noqa: F401
from nitrobox.image.store import (
    ImageConfig,
    get_image_config,
    _safe_cache_key,
    _get_image_diff_ids,
    _default_rootfs_cache_dir,
    _image_store_get,
    _image_store_populate,
    _get_image_digest,
    _get_manifest_diff_ids,
    _write_manifest,
)
from nitrobox.image.layers import (
    prepare_rootfs_layers_from_docker,
    rmtree_mapped,
)
