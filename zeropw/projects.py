"""Project and environment registry (dev / staging / prod separation)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .errors import InvalidInput, NotFound
from .store import StateDir, iso

DOC = "projects.json"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
DEFAULT_ENVIRONMENTS = ("dev", "staging", "prod")


def validate_name(value: str, what: str) -> str:
    if not isinstance(value, str) or not NAME_RE.match(value):
        raise InvalidInput(f"invalid_{what}")
    return value


@dataclass(frozen=True)
class Project:
    name: str
    environments: tuple[str, ...]
    created_at: str


class Projects:
    def __init__(self, state: StateDir) -> None:
        self.state = state

    def _load(self) -> dict:
        return self.state.read_json(DOC, {}) or {}

    def create(self, name: str, environments: tuple[str, ...] | list[str] = DEFAULT_ENVIRONMENTS) -> Project:
        validate_name(name, "project")
        envs = tuple(validate_name(e, "environment") for e in environments)
        if not envs:
            raise InvalidInput("no_environments")
        with self.state.lock():
            doc = self._load()
            if name in doc:
                raise InvalidInput("project_exists")
            doc[name] = {"environments": list(envs), "created_at": iso()}
            self.state.write_json(DOC, doc)
        return Project(name, envs, doc[name]["created_at"])

    def get(self, name: str) -> Project:
        doc = self._load()
        entry = doc.get(name)
        if entry is None:
            raise NotFound("project_not_found")
        return Project(name, tuple(entry["environments"]), entry["created_at"])

    def require_environment(self, project: str, environment: str) -> None:
        entry = self.get(project)
        if environment not in entry.environments:
            raise NotFound("environment_not_found")

    def list(self) -> list[Project]:
        doc = self._load()
        return [Project(n, tuple(v["environments"]), v["created_at"]) for n, v in sorted(doc.items())]
