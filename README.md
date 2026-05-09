# cloud-sg-bot

A small daemon that updates Tencent Cloud security group ingress rules from target-specific public IP probes.

It is intended for multi-egress networks where different destination servers observe different public source IPs. Each job fetches the IP from its own probe URL, then updates only the configured security groups for that job.

Supported features:

- Fetches one public IPv4 per job from a configured probe URL
- Converts the observed IP to a `/32` CIDR
- Syncs Tencent Cloud ingress rules across one or more security group targets
- Replaces only managed rules that match the configured remark prefix, job name, and rule protocol
- Leaves manual rules, other prefixes, and other jobs' rules untouched
- Supports TCP, UDP, ICMP/GRE/ALL, and Tencent Cloud service template rule expressions

## Install

Install the latest Linux release:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cloud-sg-bot/main/scripts/install.sh | sudo sh
```

Optional: install a specific version instead of the latest release:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cloud-sg-bot/main/scripts/install.sh | \
  sudo env VERSION=<release-tag> sh
```

## Install (Optional: China Proxy)

If direct access to GitHub is slow or blocked, use a mirrored script URL, set `GITHUB_PROXY`, and install an explicit release tag.

Use a specific version instead of relying on the default `latest` resolution.

Install or upgrade through `ghproxy.net`:

```sh
curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/panjiang/cloud-sg-bot/main/scripts/install.sh | \
  sudo env GITHUB_PROXY=https://ghproxy.net VERSION=<release-tag> sh
```

## Configure

If you want to start from the installed example file and `/etc/cloud-sg-bot/config.yaml` does not already exist:

```sh
sudo cp -n /etc/cloud-sg-bot/config.yaml.example /etc/cloud-sg-bot/config.yaml
```

This avoids overwriting an existing runtime configuration.

Edit the runtime config:

The installer creates this file with `0600` permissions if it does not already exist.

```sh
sudo vi /etc/cloud-sg-bot/config.yaml
```

Example configuration:

```yaml
checkInterval: 10m
remarkPrefix: bot

log:
  level: info

providerConfigs:
  tencentcloud:
    secretId: xxx
    secretKey: xxx

jobs:
  - name: prod
    ipSource:
      url: http://prod.yourdomain.com:55555/
      timeout: 5s
    rules:
      - TCP:22,4646,8880,3000,9090,9093,3306,6379,8885,80,8123
      - UDP:53
      - ICMP
    targets:
      - name: prod-web
        region: ap-singapore
        securityGroupId: sg-yyyyyyyy
```

Configuration notes:

- Durations use Go-style units plus day and week units: `ms`, `s`, `m`, `h`, `d`, and `w`.
- `checkInterval` defaults to `10m` and must be at least `10s`.
- `ipSource.timeout` defaults to `5s` and must be greater than zero.
- `log.level` can be `debug`, `info`, `warn`, or `error`.
- `providerConfigs.tencentcloud.secretId` and `providerConfigs.tencentcloud.secretKey` are required.
- Keep private probe URLs, real security group IDs, and Tencent Cloud credentials out of Git.

`rules` entries use Tencent Cloud protocol-port expressions:

- `TCP:80`
- `UDP:80,443`
- `TCP:3306-20000`
- `ALL`
- `ppm-1234ilbd`
- `ppmg-1234ilbd`
- `ICMP`, `ICMPv6`, or `GRE`

The program only maps each expression into Tencent Cloud API fields. It does not validate port syntax, protocol validity, or template existence; Tencent Cloud API errors are logged and returned.

Managed rules are identified by `PolicyDescription`:

```text
<remarkPrefix>:<job-name>:<rule-protocol>
```

Only matching managed rules are replaced. Manual rules and other jobs' rules are left unchanged.

`remarkPrefix` is optional and defaults to `bot`. Use a different prefix such as `bot:server238` when multiple machines manage the same security group and must not touch each other's rules.

Older descriptions from previous versions are not migrated automatically and should be cleaned up manually after upgrade if they are no longer needed.

Because the description contains only the job name and rule protocol, keep one rule entry per protocol in each job. For example, write one `TCP:22,443` entry instead of two separate `TCP` entries.

## Daemon

Start the service after the config is ready:

```sh
sudo systemctl enable --now cloud-sg-bot
sudo systemctl status cloud-sg-bot
```

View service logs:

```sh
sudo journalctl -u cloud-sg-bot -f
```

## Local Development

Run locally with the example config:

```sh
go run . -config=config.yaml
```

Print the version string:

```sh
go run . -version
```

Build:

```sh
go build -o cloud-sg-bot .
```

Run tests:

```sh
go test ./...
```

## Upgrade

Existing installations under the previous project name are not migrated automatically. Copy the old runtime config to `/etc/cloud-sg-bot/config.yaml`, enable `cloud-sg-bot`, and disable the previous service after verifying the new one is healthy.

Upgrade to the latest release and restart the service:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cloud-sg-bot/main/scripts/install.sh | sudo sh
sudo systemctl restart cloud-sg-bot
```

Optional: upgrade to a specific version:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cloud-sg-bot/main/scripts/install.sh | \
  sudo env VERSION=<release-tag> sh
sudo systemctl restart cloud-sg-bot
```
