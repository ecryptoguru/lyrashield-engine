"""LyraShield scans must construct the LyraShield Docker adapter."""

from lyrashield.runtime import backends


def test_product_runtime_selects_the_product_docker_backend() -> None:
    assert backends.get_backend("docker") is backends.docker_backend
