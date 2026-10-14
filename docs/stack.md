# Pinned execution-stack gate

This is the local gate for [issue 17](https://github.com/JoranBergfeld/citadel-example/issues/17),
not a working Citadel deployment. The [provisioning decision](https://github.com/JoranBergfeld/citadel-example/issues/7#issuecomment-6173968755)
owns the pins. An unavailable version, hash mismatch or incompatible required
interface blocks affected work; do not select an alternative automatically.

## Reproduce locally

Use Linux amd64, **CPython 3.12.15** and **uv 0.12.21**. `stack.toml`
records the approved base image, protocols, model and tool artifact hashes.
`pyproject.toml` pins all nineteen selected application distributions.
`uv.lock` includes every transitive dependency and the separately grouped build
backend. The two requirements exports include hashes for non-uv consumers.

```sh
# Point at an already installed, exact CPython 3.12.15 interpreter.
uv sync --locked --python /path/to/python3.12
uv run --no-sync python -m unittest discover -s tests/stack -v

# Optional package build, with the hash-locked build backend.
uv sync --locked --group build --python /path/to/python3.12
uv build --no-build-isolation
```

The system Python is not a permitted substitute. uv 0.12.21's bundled download
catalog did not contain 3.12.15 during verification; an exact interpreter must
be supplied explicitly. The verification session executed Python extracted
from the hash-verified Python layer of the approved image, using its matching
`libpython` via `LD_LIBRARY_PATH`. This checks actual CPython and SDK execution
on the host, **not execution inside a complete container**.

With a working Docker installation, the smoke-only container baseline is:

```sh
docker build --platform linux/amd64 -t citadel-stack-smoke .
docker run --rm --network none citadel-stack-smoke
```

The Dockerfile fixes the Linux amd64 child digest and installs only hashed
wheels. It copies only the package bootstrap and stack tests, runs nonroot,
and is **not** any of the five agent/tool applications. Docker was unavailable
in the verification WSL environment; its build/run and final image digest
remain unverified. No daemon configuration was changed.

## What the tests prove

- The exact CPython release and real imports of all selected distributions.
- Framework `A2AExecutor` and `A2AAgent` communicate through the official SDK's
  real FastAPI JSON-RPC routes with v0.3 compatibility disabled.
  `run(..., background=True)` returns a continuation token before the fixture
  agent is released. `poll_task(token)` makes one `GetTask` request and returns
  while work is pending; further bounded polling obtains the completed result.
- The actual MCP client initializes, negotiates `2025-11-25`, discovers a tool
  and invokes it through a real stateless JSON-response Streamable HTTP server.
- The real OpenAI adapter/client serializes a Chat Completions request to an
  explicit gateway-shaped `/openai/v1/chat/completions` URL with the supplied
  subscription header. Only external model HTTP is simulated; no inference is
  claimed. SDK retries are disabled in this fixture.
- Azure async Blob and Key Vault clients accept explicit data API versions and
  an explicitly selected managed-identity client ID. No token is acquired, secret
  retrieved or storage request sent.

The seams are installed-runtime imports and public protocol/client boundaries.
Fixtures are inert test agents/tools, not substitutes for deployed agents,
reference data, authorization or live model inference. In-memory A2A state is
deliberately limited to this smoke test.

### API facts that differ from plausible examples

- SDK **1.2.1 has no `a2a.server.apps.A2AStarletteApplication`**. Use the actual
  public `a2a.server.routes.create_jsonrpc_routes` and
  `add_a2a_routes_to_fastapi` APIs. `DefaultRequestHandler` is the V2 handler and
  requires an `agent_card`. The Framework README's older hosting example
  does not establish those import paths.
- Framework **`OpenAIChatCompletionClient`** is the Chat Completions adapter.
  `OpenAIChatClient` uses the Responses API; do not infer behavior from its name.
- OpenAI 3.23.0 consumes **HTTPX2** clients; A2A and MCP consume **HTTPX** clients.
- `A2AAgent.run(continuation_token=...)` subscribes to SSE. It is not the required
  single-request polling interface.
- A2A's wire agent-card version is `"1.0"` for specification `1.0.0`; these are
  not SDK version numbers.

The tests accelerate repeated final-state polling and impose short enclosing
timeouts. They do **not** implement or certify the production 15-second polling
cadence, 900-second logical deadline, 512-attempt accounting, owner-scoped durable
operations, restart fencing or authorization. Those remain separate work.

## Provisioning tools

`stack.toml` fixes uv, azd 1.35.1 and Bicep 0.48.1 artifacts with SHA-256.
`toolchain/azure-cli.lock` separately locks Azure CLI 2.91.0 and its complete
transitive dependencies for CPython 3.12/Linux amd64. Never install that tooling
lock into the application environment: its Azure libraries are different.
Verify downloaded bytes against the manifest before using any tool.

```sh
# Separate environment; this does not sign in or provision anything.
uv venv --python /path/to/python3.12 .venv-azure-cli
uv pip sync --python .venv-azure-cli/bin/python --require-hashes toolchain/azure-cli.lock
```

For provisioning, explicitly select the pinned Bicep executable actually used
by azd. Do not permit an implicit Bicep download/upgrade or CLI extension install.
No infrastructure templates, extension selection or deployment are supplied here.

## Lock maintenance and remaining gates

After an approved dependency change only:

```sh
uv lock
uv export --locked --no-dev --no-emit-project --no-header --output-file requirements.lock
uv export --locked --only-group build --no-emit-project --no-header --output-file build-requirements.lock
uv pip compile toolchain/azure-cli.in --python .venv/bin/python \
  --python-platform x86_64-unknown-linux-gnu --only-binary :all: \
  --generate-hashes --no-header --output-file toolchain/azure-cli.lock
```

The official regional model table currently lists `gpt-4.1-mini` version
`2025-04-14` in West Europe under **Standard/Regional**, not just Global/Data
Zone. This is documentation, not live quota, deployment or inference proof.
The retirement page's fine-tuning dates do not establish a base-model lifetime.
Actual provider/API behavior, model lifecycle/capacity, resource API inventory,
Bicep deployment compilation, gateway paths, authorization and two complete
cloud acceptance passes remain mandatory future gates.

Commands, primary response metadata, downloaded-artifact checksums and test
outputs are retained outside Git in the operator's session evidence bundle.
No account access, login, provisioning, push or tracker mutation is required
for these local tests.
