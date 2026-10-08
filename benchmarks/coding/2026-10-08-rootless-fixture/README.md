# Governed coding fixture on Linux/rootless containers

[Exact GitHub run](https://github.com/surya-koritala/AIagentOS/actions/runs/37745077639)
executed source head `623b1927cc0590b9116c7fda54be0f4be14def0f` through the tested
merge commit in [source metadata](source.json), with the recorded immutable Rust
image. This is deterministic fixture evidence, with zero provider API calls.
It does not establish real-model quality, invoice costs or production qualification.

The first UTF-8 candidate ran the immutable named Rust test target and failed
with exit 101 in 553 ms. Its branch was discarded and erased. A fresh application
process loaded the durable job, retained the prepared parent history, selected
the second candidate after actual isolated tests passed with exit 0 in 531 ms,
and reported one changed source file. The protected tests and manifests remained
unchanged. A second resume returned identical completed JSON and the same
synthetic fixture token counter (2,131), proving it issued no new provider turn.
Configured fixture cost was zero. No original repository was written.

Raw [paused report](paused.json), [completed report](completed.json),
[repeat report](replayed-report.json), and both event logs are retained with
SHA-256 digests in the metadata. All test evidence is `isolated_process`, unlike
the application's separate public-wire tests labelled `contract_fixture`.
The workflow also checked that no sandbox container remained after execution.

Reproduce with the fixture and resume commands in
[the application instructions](../../../crates/coding-agent/README.md).
Task outcomes here are scripted; reviewed real-provider tasks, comparison runs,
clean-host downloadable package verification and independent review remain #394.
