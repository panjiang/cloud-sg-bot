# Repository Guidelines

## Project Structure & Module Organization
This repository is a small Go daemon/CLI in a single `main` package. Runtime flow starts in `main.go`, configuration loading and validation live in `config.go`, periodic orchestration is in `updater.go`, Tencent Cloud security group operations are in `tencentcloud.go`, rule parsing and policy conversion are in `rule.go`, public IP probing is in `ip_source.go`, logging is in `logger.go`, and duration/version helpers live in `duration.go` and `version.go`. Tests are colocated with implementation in `*_test.go` files. `config.yaml` is the sanitized example configuration, while local private configs such as `config.my.yaml` must not be committed. `scripts/install.sh` installs a built binary as a systemd service.

## Build, Test, and Development Commands
Use standard Go tooling:

- `go run . -config=config.yaml` runs the updater locally with the example config.
- `go run . -version` prints the current version string.
- `go build .` builds the default binary in the repository root.
- `go build -o cloud-sg-bot .` builds the binary expected by `scripts/install.sh`.
- `go test ./...` runs all unit tests.
- `go test -cover ./...` reports test coverage.
- `gofmt -w *.go` formats the Go source files in this single-package repo.

## Coding Style & Naming Conventions
Follow idiomatic Go and keep files `gofmt`-clean. Prefer small focused functions and table-driven tests for parsing, validation, and Tencent Cloud policy diffing. Exported identifiers use `CamelCase`; unexported helpers use `camelCase`; test names should read like `TestConfigComplete` or `TestParseRuleExpression`.

Keep YAML keys aligned with existing config fields such as `checkInterval`, `remarkPrefix`, `providerConfigs.tencentcloud`, `jobs`, `ipSource`, `rules`, and `targets`. Preserve the current single-provider shape unless the change explicitly introduces provider abstraction.

## Behavior Notes
The daemon fetches one public IPv4 per job from `ipSource.url`, converts it to a `/32` CIDR, then syncs only that job's configured security group targets. Managed Tencent Cloud ingress rules are identified by `PolicyDescription`:

```text
<remarkPrefix>:<job-name>:<rule-protocol>
```

Only matching managed rules should be replaced. Manual rules, rules with other prefixes, and rules from other jobs must be left untouched. Because the managed description contains the protocol bucket, config validation rejects duplicate managed protocols per job; keep one rule entry per protocol, for example `TCP:22,443` rather than two separate `TCP` entries.

`rules` values are Tencent Cloud protocol-port expressions. The program maps expressions to Tencent Cloud API fields but intentionally does not validate every Tencent Cloud port syntax, protocol validity, or service template existence; those errors come back from the API.

## Testing Guidelines
Add or update tests whenever behavior changes. Focus coverage on:

- config defaults and validation in `config_test.go`;
- duration parsing edge cases;
- IP source fetching behavior;
- rule parsing, managed descriptions, and policy matching;
- Tencent Cloud create/delete decisions using mocked `securityGroupAPI`;
- updater behavior when jobs or targets partially fail.

Run `go test ./...` before handing off code changes. For docs-only changes, tests are not required unless the documentation change reflects a behavior change that should be verified.

## Security & Configuration Tips
Never commit real Tencent Cloud `secretId` or `secretKey` values, live security group IDs tied to private infrastructure, or private probe URLs. Keep `config.yaml` sanitized and treat it as a template. Do not log secrets. Be careful with `remarkPrefix`: changing it changes which rules the bot manages and can leave older managed rules behind for manual cleanup.

The installer writes `/etc/cloud-sg-bot/config.yaml` with `0600` permissions and runs the service as root. If changing install behavior, document the operational impact and verify the generated systemd unit still starts the expected binary with `-config=/etc/cloud-sg-bot/config.yaml`.

## Commit & Pull Request Guidelines
Git history is not available in this workspace, so no repository-specific commit convention could be verified. Use short imperative commit subjects such as `validate duplicate rule protocols` or `handle empty ip source responses`. PRs should describe operational impact, mention config changes, and include relevant `go test ./...` output.

## Release Guidelines
Do not create or push git tags, GitHub Releases, or release-triggering refs unless the user explicitly asks to publish a version. Normal code changes may be committed and pushed when requested, but release publication requires a separate clear instruction.
