# Public evidence declarations

`capabilities.toml` is the maturity authority. Current assertions of a capability
status use an inline declaration next to the visible tier, for example:

```markdown
<!-- capability-claim: tool-vfs=integrated -->Recorded evidence: Integrated.
```

The capability gate compares each declaration with the registry ceiling and
checks that its tier is visible. Current status tables cannot use an unbound
Done, Live or maturity label. README's complete status block must match the
registry row by row. A real registry downgrade fails with the affected public
path; the CI negative control changes only its disposable checkout and restores
it before finishing.

`public-claims.toml` inventories README and every Markdown page under `docs/`.
Adding or removing a page requires an explicit audit classification. Historical
specifications identify that status near their heading and point to #105 and the
registry. Code examples, conditional qualification criteria, host requirements
and Linux module names are not capability promotions. Prose is reviewed in the
source audit; the gate validates declared claims and current status cells rather
than inferring support from every ordinary use of words such as live or supported.

Crate descriptions identify the user-space runtime/client/helper role without
claiming whole-product qualification. Public installer, real-model, target
filesystem and independent review evidence remain separate. GitHub description
and topics are an external surface. The applied values are recorded in
[Repository framing](REPOSITORY_METADATA_PROPOSAL.md); CI reads GitHub metadata
and verifies an exact match without changing it.
