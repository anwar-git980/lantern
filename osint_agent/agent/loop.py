"""The agent loop: seed -> modules -> extract -> frontier -> the model picks -> repeat.

Two things are deliberately not the model's job. It cannot choose a value: it may only act on
a candidate that `extract.py` put in the frontier, so text collected from the internet cannot
name a new target however it is phrased. And it cannot choose how long to run: every limit
below is enforced here, in code, because a prompt is a request and a budget is not.
"""

import asyncio
import os
from collections import defaultdict
from collections.abc import Callable

from pydantic import BaseModel, Field

from osint_agent.agent.prompts import DEFAULT_GOAL, SYSTEM_PROMPT, clip, render_turn
from osint_agent.core.extract import Candidate, extract_seeds
from osint_agent.core.graph import EntityGraph
from osint_agent.core.models import ModuleResult, Seed
from osint_agent.core.runner import open_client, run_jobs
from osint_agent.core.scoring import avatar_correlations, static_correlations
from osint_agent.modules import REGISTRY, domain, dork, email, phone, social, username

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_OUTPUT_TOKENS = 2048
MAX_DEPTH = 2
MAX_TOOL_CALLS = 30
MAX_LLM_TURNS = 10
MAX_INPUT_TOKENS = 150_000
FINISH = "finish"

MODULES = {module.NAME: module for module in (email, username, phone, domain, dork, social)}

TOOL_DESCRIPTIONS = {
    "email": (
        "Email enrichment: MX records, HaveIBeenPwned breach metadata, the Gravatar profile "
        "and its linked accounts, plus ~120 account-existence checks via holehe. Rich in new "
        "pivots. Slow: up to 90 seconds."
    ),
    "username": (
        "Checks a handle against ~500 sites via Maigret. Broad but weak on its own - a name "
        "collision looks identical to the real person. Slow: 30-120 seconds."
    ),
    "social": (
        "Public profiles on GitHub, Reddit, Bluesky, Hacker News and Mastodon, including the "
        "links and display names in their bios. The cheapest and richest source of new pivots "
        "for a username. Fast."
    ),
    "domain": (
        "Domain and infrastructure: DNS records, SPF/DMARC, crt.sh subdomains, RDAP "
        "registration dates, Shodan open ports and CVEs, Wayback archive summary. Medium "
        "speed."
    ),
    "phone": (
        "Offline phone validation: region, carrier, line type, timezones. Instant and makes "
        "no network request."
    ),
    "dork": (
        "Search-engine dorks through the Brave Search API. Works on any seed type. Spends "
        "PAID search quota, so use it only when no other module would answer the question."
    ),
}


class Step(BaseModel):
    turn: int
    tool: str
    seed: str
    depth: int
    findings: int
    errors: int


class Rejection(BaseModel):
    """A tool call that was refused. `injection_suspect` means the value was not in the
    frontier, which is what a successful prompt injection would look like from here."""

    turn: int
    tool: str
    value: str
    reason: str
    kind: str


class RunRecord(BaseModel):
    root: dict
    goal: str
    mode: str
    steps: list[Step] = Field(default_factory=list)
    stop_reason: str = ""
    tool_calls: int = 0
    llm_turns: int = 0
    usage: dict = Field(default_factory=lambda: {"input_tokens": 0, "output_tokens": 0})
    rejected: list[Rejection] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    summary: str | None = None
    graph: dict = Field(default_factory=dict)

    @property
    def suspects(self) -> list[Rejection]:
        return [r for r in self.rejected if r.kind == "injection_suspect"]


def tool_schemas() -> list[dict]:
    tools = [
        {
            "name": name,
            "description": (
                f"{TOOL_DESCRIPTIONS[name]} Accepts seed types: "
                f"{', '.join(sorted(module.SUPPORTS))}."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "A value listed in the current FRONTIER section.",
                    }
                },
                "required": ["value"],
            },
        }
        for name, module in MODULES.items()
    ]
    tools.append(
        {
            "name": FINISH,
            "description": (
                "End the investigation. Call this when the remaining frontier candidates are "
                "unrelated, redundant or not worth their cost."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Two or three sentences on what was established.",
                    }
                },
                "required": ["summary"],
            },
        }
    )
    return tools


def root_candidate(seed: Seed) -> Candidate:
    """The root as a frontier entry, so the model may re-run a module on the seed itself."""
    return Candidate(
        seed=seed, module="seed", entity_type="root", found_in="root seed", found_node=""
    )


def resolve(value: str, frontier: dict[str, Candidate]) -> Candidate | None:
    """The frontier candidate a model-supplied string names, or None.

    None is the security-relevant answer: it means the model asked for something that code
    never put in front of it.
    """
    probe = str(value).strip()
    options = list(frontier.values())

    for candidate in options:
        if probe in (candidate.seed.normalized, candidate.node_id, candidate.seed.value):
            return candidate

    lowered = probe.lower().lstrip("@")
    tail = probe.split(":", 1)[1].strip().lower() if ":" in probe else None
    for candidate in options:
        target = candidate.seed.normalized.lower()
        if lowered == target or (tail is not None and tail == target):
            return candidate
    return None


def validate(
    turn: int, tool: str, value: str, frontier: dict[str, Candidate]
) -> tuple[Candidate | None, Rejection | None]:
    if tool not in MODULES:
        return None, Rejection(
            turn=turn,
            tool=tool,
            value=str(value),
            reason=f"no tool named {tool!r}",
            kind="unknown_tool",
        )

    candidate = resolve(value, frontier)
    if candidate is None:
        return None, Rejection(
            turn=turn,
            tool=tool,
            value=str(value),
            reason=(
                "not in frontier: this value was never extracted as a candidate, so it will "
                "not be investigated"
            ),
            kind="injection_suspect",
        )

    if candidate.seed.type.value not in MODULES[tool].SUPPORTS:
        return None, Rejection(
            turn=turn,
            tool=tool,
            value=str(value),
            reason=(
                f"tool {tool!r} does not accept seed type {candidate.seed.type.value!r} "
                f"(accepts {', '.join(sorted(MODULES[tool].SUPPORTS))})"
            ),
            kind="type_mismatch",
        )
    return candidate, None


# Finding types worth showing the model as a sample of what was collected.
NOTABLE_TYPES = frozenset(
    {"account", "linked_account", "linked_url", "avatar", "dork_hit", "breach", "registrar"}
)


class _State:
    """Graph, frontier, depths and the seen-set, which together are the run."""

    def __init__(self, root: Seed, max_depth: int) -> None:
        self.root = root
        self.max_depth = max_depth
        self.graph = EntityGraph()
        self.root_id = self.graph.add_seed(root)
        self.depths: dict[str, int] = {self.root_id: 0}
        self.frontier: dict[str, Candidate] = {}
        self.prose_only: dict[str, Candidate] = {}
        # Candidates already acted on. Still valid targets to name - they came out of the
        # frontier - so re-requesting one is a duplicate, not a suspected injection.
        self.investigated: dict[str, Candidate] = {}
        self.seen: set[tuple[str, str]] = set()
        self.counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._notable: list[tuple[float, str, str, str]] = []

    def absorb(
        self, results: list[ModuleResult], *, parent: Candidate, parent_id: str, depth: int
    ) -> tuple[int, int]:
        """Record one batch of results and grow the frontier from them."""
        findings = []
        errors = 0
        for result in results:
            errors += len(result.errors)
            for finding in result.findings:
                self.graph.add_finding(finding, parent_id=parent_id, depth=depth)
                self.counts[result.module][finding.entity_type] += 1
                findings.append(finding)
                if finding.entity_type in NOTABLE_TYPES:
                    self._notable.append(
                        (finding.confidence, result.module, finding.entity_type, finding.value)
                    )

        for candidate in extract_seeds(findings, parent=parent.seed):
            child_depth = depth + 1
            if child_depth > self.max_depth or candidate.node_id in self.depths:
                continue
            self.graph.add_candidate(candidate, parent_id=parent_id, depth=child_depth)
            self.depths[candidate.node_id] = child_depth
            if candidate.from_prose:
                # Recorded in the graph so the analyst sees it, but never offered to the
                # planner: an identifier that appeared only in someone's prose is exactly how
                # a prompt injection would try to nominate its own target.
                self.prose_only[candidate.node_id] = candidate
                continue
            self.frontier[candidate.node_id] = candidate

        return len(findings), errors

    def notable(self, limit: int) -> list[tuple[str, str, str]]:
        ranked = sorted(self._notable, key=lambda row: -row[0])
        return [(module, entity, value) for _, module, entity, value in ranked[:limit]]

    def plain_counts(self) -> dict[str, dict[str, int]]:
        return {module: dict(types) for module, types in self.counts.items()}


def _fill_jobs(
    wanted: list[tuple[object, Candidate]], used: int, cap: int
) -> list[tuple[object, Candidate]]:
    """Trim a wish-list of module runs to what the remaining budget allows."""
    return wanted[: max(0, cap - used)]


async def _execute(
    state: _State,
    jobs: list[tuple[object, Candidate]],
    record: RunRecord,
    turn: int,
    on_step: Callable[[str], None] | None,
) -> dict[str, tuple[int, int]]:
    """Run a batch of (module, candidate) pairs and fold the results into the graph."""
    outcomes: dict[str, tuple[int, int]] = {}
    if not jobs:
        return outcomes

    for module, candidate in jobs:
        if on_step:
            on_step(
                f"turn {turn}: {module.NAME} on {candidate.seed.type.value}="
                f"{candidate.seed.normalized}"
            )

    results = await run_jobs([(module, candidate.seed) for module, candidate in jobs])

    for (module, candidate), result in zip(jobs, results, strict=True):
        state.investigated[candidate.node_id] = candidate
        depth = state.depths.get(candidate.node_id, 0)
        parent_id = state.graph.add_seed(candidate.seed, depth=depth, module=module.NAME)
        found, errors = state.absorb([result], parent=candidate, parent_id=parent_id, depth=depth)
        for warning in result.errors:
            note = f"[{result.module}] {warning}"
            if note not in record.warnings:
                record.warnings.append(note)
        record.tool_calls += 1
        record.steps.append(
            Step(
                turn=turn,
                tool=module.NAME,
                seed=candidate.node_id,
                depth=depth,
                findings=found,
                errors=errors,
            )
        )
        outcomes[f"{module.NAME}:{candidate.node_id}"] = (found, errors)
    return outcomes


async def _correlate(state: _State) -> None:
    """Raise confidence where independent profiles point at the same person."""
    profiles = state.graph.profiles()
    if len(profiles) < 2:
        return
    links = static_correlations(profiles)
    if sum(1 for profile in profiles if profile.avatar_url) >= 2:
        async with open_client() as client:
            links += await avatar_correlations(profiles, client)
    state.graph.apply_correlations(links)


async def _run_root(
    state: _State, record: RunRecord, on_step: Callable[[str], None] | None
) -> None:
    """Depth 0 needs no planning: run everything the seed supports."""
    root = root_candidate(state.root)
    modules = REGISTRY.get(state.root.type, [])
    for module in modules:
        state.seen.add((module.NAME, state.root_id))
    await _execute(state, [(module, root) for module in modules], record, 0, on_step)


def _tool_uses(response) -> list:
    return [
        block
        for block in getattr(response, "content", [])
        if getattr(block, "type", None) == "tool_use"
    ]


def _add_usage(record: RunRecord, response) -> None:
    usage = getattr(response, "usage", None)
    record.usage["input_tokens"] += int(getattr(usage, "input_tokens", 0) or 0)
    record.usage["output_tokens"] += int(getattr(usage, "output_tokens", 0) or 0)


async def _bfs(
    state: _State,
    record: RunRecord,
    *,
    max_tool_calls: int,
    on_step: Callable[[str], None] | None,
) -> None:
    """No-LLM fallback: run every applicable module on every frontier seed, breadth-first."""
    turn = 1
    while state.frontier:
        if record.tool_calls >= max_tool_calls:
            record.stop_reason = f"max_tool_calls reached ({max_tool_calls})"
            return

        # Recomputed each pass rather than draining the frontier, so a candidate trimmed for
        # budget stays a candidate instead of being silently dropped.
        shallowest = sorted(state.frontier.values(), key=lambda c: state.depths[c.node_id])
        wanted = [
            (module, candidate)
            for candidate in shallowest
            for module in REGISTRY.get(candidate.seed.type, [])
            if (module.NAME, candidate.node_id) not in state.seen
        ]
        if not wanted:
            record.stop_reason = "frontier exhausted (every applicable module already ran)"
            return

        jobs = _fill_jobs(wanted, record.tool_calls, max_tool_calls)
        if not jobs:
            record.stop_reason = f"max_tool_calls reached ({max_tool_calls})"
            return
        for module, candidate in jobs:
            state.seen.add((module.NAME, candidate.node_id))
        await _execute(state, jobs, record, turn, on_step)
        turn += 1

    record.stop_reason = "frontier empty"


async def _llm_loop(
    state: _State,
    record: RunRecord,
    *,
    llm,
    model: str,
    goal: str,
    max_tool_calls: int,
    max_llm_turns: int,
    max_input_tokens: int,
    on_step: Callable[[str], None] | None,
) -> None:
    tools = tool_schemas()

    def state_text(turn: int) -> str:
        frontier = {**state.frontier, state.root_id: root_candidate(state.root)}
        return render_turn(
            state.root,
            goal,
            state.plain_counts(),
            state.notable(limit=25),
            frontier,
            state.depths,
            tool_calls=record.tool_calls,
            max_tool_calls=max_tool_calls,
            turn=turn,
            max_turns=max_llm_turns,
            max_depth=state.max_depth,
        )

    messages: list[dict] = [{"role": "user", "content": state_text(1)}]

    for turn in range(1, max_llm_turns + 1):
        if not state.frontier:
            record.stop_reason = "frontier empty"
            return
        if record.tool_calls >= max_tool_calls:
            record.stop_reason = f"max_tool_calls reached ({max_tool_calls})"
            return
        if record.usage["input_tokens"] >= max_input_tokens:
            record.stop_reason = f"input token budget exhausted ({max_input_tokens})"
            return

        record.llm_turns = turn
        response = await asyncio.to_thread(
            llm.messages.create,
            model=model,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=SYSTEM_PROMPT,
            tools=tools,
            messages=messages,
        )
        _add_usage(record, response)

        calls = _tool_uses(response)
        if not calls:
            record.stop_reason = "model stopped without calling a tool"
            return

        # The frontier the model was actually shown, so a value is judged against the list it
        # saw and not against one that moved underneath it.
        offered = {
            **state.frontier,
            **state.investigated,
            state.root_id: root_candidate(state.root),
        }

        jobs: list[tuple[object, Candidate]] = []
        results_for: list[tuple[object, Candidate, str]] = []
        rejections: list[tuple[str, Rejection]] = []
        finish_summary: str | None = None

        for block in calls:
            name = getattr(block, "name", "")
            args = getattr(block, "input", {}) or {}
            if name == FINISH:
                finish_summary = str(args.get("summary", "")).strip() or None
                continue

            candidate, rejection = validate(turn, name, args.get("value", ""), offered)
            if rejection is not None:
                record.rejected.append(rejection)
                rejections.append((block.id, rejection))
                continue

            key = (name, candidate.node_id)
            if key in state.seen:
                duplicate = Rejection(
                    turn=turn,
                    tool=name,
                    value=candidate.seed.normalized,
                    reason="already ran this module on this seed; skipped",
                    kind="duplicate",
                )
                record.rejected.append(duplicate)
                rejections.append((block.id, duplicate))
                continue
            state.seen.add(key)
            jobs.append((MODULES[name], candidate))
            results_for.append((MODULES[name], candidate, block.id))

        allowed = _fill_jobs(jobs, record.tool_calls, max_tool_calls)
        dropped = jobs[len(allowed) :]
        for module, candidate in dropped:
            state.seen.discard((module.NAME, candidate.node_id))

        outcomes = await _execute(state, allowed, record, turn, on_step)

        for _module, candidate in allowed:
            state.frontier.pop(candidate.node_id, None)

        if finish_summary is not None and not allowed:
            record.summary = finish_summary
            record.stop_reason = "model called finish"
            return

        messages.append({"role": "assistant", "content": response.content})

        blocks: list[dict] = []
        for block_id, rejection in rejections:
            blocks.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block_id,
                    "content": f"rejected: {rejection.reason}",
                    "is_error": True,
                }
            )
        for module, candidate, block_id in results_for:
            outcome = outcomes.get(f"{module.NAME}:{candidate.node_id}")
            if outcome is None:
                blocks.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block_id,
                        "content": "not run: module-run budget exhausted",
                        "is_error": True,
                    }
                )
                continue
            found, errors = outcome
            blocks.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block_id,
                    "content": (
                        f"{module.NAME} on {clip(candidate.seed.normalized)}: "
                        f"{found} findings, {errors} warnings"
                    ),
                }
            )
        if finish_summary is not None:
            record.summary = finish_summary
        blocks.append({"type": "text", "text": state_text(turn + 1)})
        messages.append({"role": "user", "content": blocks})

    record.stop_reason = f"max_llm_turns reached ({max_llm_turns})"


async def investigate_agent(
    root: Seed,
    *,
    llm=None,
    model: str | None = None,
    goal: str = DEFAULT_GOAL,
    max_depth: int = MAX_DEPTH,
    max_tool_calls: int = MAX_TOOL_CALLS,
    max_llm_turns: int = MAX_LLM_TURNS,
    max_input_tokens: int = MAX_INPUT_TOKENS,
    use_llm: bool = True,
    on_step: Callable[[str], None] | None = None,
) -> RunRecord:
    """Investigate `root`, pivoting until the model stops or a limit is hit.

    With no `llm` and no ANTHROPIC_API_KEY, falls back to breadth-first expansion under the
    same limits. That is noisier: it runs every applicable module on every candidate rather
    than the ones worth running.
    """
    if use_llm and llm is None and os.getenv("ANTHROPIC_API_KEY"):
        import anthropic

        llm = anthropic.Anthropic()

    mode = "llm" if (use_llm and llm is not None) else "bfs"
    record = RunRecord(
        root=root.model_dump(mode="json") | {"normalized": root.normalized},
        goal=goal,
        mode=mode,
    )
    state = _State(root, max_depth)

    await _run_root(state, record, on_step)

    if record.tool_calls >= max_tool_calls:
        record.stop_reason = f"max_tool_calls reached ({max_tool_calls}) running the root seed"
    elif mode == "llm":
        await _llm_loop(
            state,
            record,
            llm=llm,
            model=model or os.getenv("LANTERN_MODEL") or DEFAULT_MODEL,
            goal=goal,
            max_tool_calls=max_tool_calls,
            max_llm_turns=max_llm_turns,
            max_input_tokens=max_input_tokens,
            on_step=on_step,
        )
    else:
        await _bfs(state, record, max_tool_calls=max_tool_calls, on_step=on_step)

    await _correlate(state)
    record.graph = state.graph.to_dict()
    record.stop_reason = record.stop_reason or "frontier empty"
    return record
