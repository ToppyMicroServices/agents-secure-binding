# Contributing

Thanks for considering a contribution. This repository is focused on the
TLS identity binding, its Go implementation helpers, and the accompanying
security test vectors. Hardware attestation is optional for local development.

## Try it before changing it

With Go 1.26.6 installed, run these commands from the repository root. They
work in macOS, Linux and Windows shells; no TEE hardware or Docker is needed.

```text
go run ./cmd/asb-human self-test
go run ./cmd/asb-human demo --data-dir ./.asb-human
```

The first command checks the local approval flow automatically, using a
simulated Human decision in temporary storage. The second starts a real
browser review: open its private login link, then approve or reject the Agent's
proposal. Only a Boolean in the application's own database can change.

See the [local approval guide](docs/local-human-approval.md) for expected
results, separate Agent processes and restart recovery. These commands test the
local preview, not hardware attestation or the generic TaskCoord production
profile.

## Issues

Open an issue when behavior is unclear, a security boundary is missing, or a
test vector does not match the profile. Include:

- the affected file, package, or vector;
- the expected behavior;
- the observed behavior;
- the smallest reproduction or failing test, when available.

## Pull Requests

Keep pull requests focused. A good pull request changes one behavior, document
section, or test surface at a time.

Use concise Conventional Commit messages:

```text
<type>(optional scope): <summary>
```

Common types are `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`,
`build`, and `perf`.

Before opening a pull request, run the relevant checks. For profile and identity
changes, start with:

```sh
go test ./pkg/agtp ./pkg/atls/identitypolicy
go test ./pkg/clients ./pkg/clients/http ./pkg/clients/grpc
```

Some client tests open local loopback listeners. Restricted sandboxes may need a
less constrained local environment for those tests.

For local approval changes, run:

```text
go test -count=1 ./internal/humanapp ./cmd/asb-human
go vet ./internal/humanapp ./cmd/asb-human
```

The `Local Human Approval` workflow also runs race tests and the documented
`self-test` on macOS, Linux and Windows. A successful local run does not replace
those OS-specific CI results.

If you change the browser logic, also run
`node --test internal/humanapp/web_ui_test.mjs` with Node 22 or later, then check
the real browser through `demo`. Node is only needed for these contributor
tests, not to run the application.

## Documentation

`docs/SSOT.md` is the source of truth for the security profile. Keep derived
notes, reports, and test-vector descriptions aligned with it.
