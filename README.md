# Citadel sample

Four governed agents and a read-only reference-data MCP service, hosted on Azure
through APIM. Fictional airport comparisons; **not operational aviation advice**.

- [Operator commands, current blocking gate, deployment and manual teardown](docs/operator.md)
- [Immutable source and fixture preparation](docs/evidence.md)
- [Infrastructure and authority boundaries](docs/infrastructure.md)
- [Runtime and durable operation contracts](docs/runtime.md)
- [Exact stack and offline wheelhouse](docs/stack.md)

Local contract tests and offline containers are not live Azure acceptance.
The operator lifecycle currently blocks paid provisioning: the approved API Center
service API has no plan-read interface. Task 20's acceptance harness and task 21's
cloud proof also remain outstanding.
