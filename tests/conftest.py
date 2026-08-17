"""Fixtures shared by the integration, failure, security and load suites.

``tests/harness.py`` holds the process management; this module makes it
importable from every subdirectory and exposes it as pytest fixtures.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import BrokerProcess, binaries_present  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "extended: opt-in long-running test")
    config.addinivalue_line("markers", "root: requires root privileges")


@pytest.fixture(scope="session", autouse=True)
def require_binaries() -> None:
    if not binaries_present():
        pytest.skip(
            "build the C binaries first, or set TUNNELMATE_BUILD_DIR",
            allow_module_level=True,
        )


@pytest.fixture
def broker_factory(tmp_path: Path):
    """Build brokers with custom settings; every one is cleaned up at teardown."""
    created: list[BrokerProcess] = []

    def factory(
        ports: int = 2, settings: dict | None = None, name: str = "broker"
    ) -> BrokerProcess:
        directory = tmp_path / name
        directory.mkdir(exist_ok=True)
        instance = BrokerProcess(directory, ports=ports, settings=settings)
        instance.start()
        created.append(instance)
        return instance

    yield factory

    for instance in created:
        instance.cleanup()
        returncode = instance.process.returncode if instance.process else None
        if returncode not in {0, -15, None}:
            pytest.fail(f"broker exited with {returncode}: {instance.log_text()}")


@pytest.fixture
def broker(broker_factory) -> BrokerProcess:
    """A single broker with a two-port public range."""
    return broker_factory()
