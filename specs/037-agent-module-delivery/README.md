# 037: Deliver module install bundles through the inventory agent

The full specification, plan, research, contracts and tasks live in the
inventory repository, which owns most of the change and the shared protocol:
`go-tangra-inventory-v4/specs/037-agent-module-delivery/`.

Gateway side (tasks T017–T020, T021 gateway docs):

- migration `0008_catalogue_join_agent.sql`: join channel, tenant, host, inputs, render counter, nullable JTI
- `internal/grpcapi/modulebundle.go`: serves `inventory.v1.ModuleBundleSource/RenderModuleBundle`
- `internal/httpapi/catalogue_deliver.go`: `GET …/{module}/targets`, `POST …/{module}/deliver`, delivery in join progress
- config `catalogue.agent_delivery.inventory_service`; policy rule `inventory-module-bundle`
- shell: the wizard offers **Deliver to a host**
