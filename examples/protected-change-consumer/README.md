# Protected Change consumer

This reference application is intentionally unrelated to Split-Knowledge. It
accepts one tenant-configuration change over mutually authenticated TLS 1.3 and
applies it only after the `pkg/production` verifier accepts:

- separate Manager and Agent trust keys plus current revocation state;
- required issue times and verifier-local maximum token lifetimes;
- the exact action context and accepted TLS exporter binding;
- a signed, fresh, policy-approved attestation result;
- a verifier-issued one-shot nonce; and
- the shared replay-store commit.

The integration test uses a real HTTPS request boundary and covers the positive
path plus changed-action, wrong-session, replay, revocation, and attestation
failures:

```sh
go test -race -count=1 ./examples/protected-change-consumer
```

The HTTP application also requires a verified client-certificate chain, rather
than accepting the presence of an unverified peer certificate.

## Run the durable recovery recipe

```sh
go test -race -count=1 -run '^TestDurableRecoveryRecipe$' -v ./examples/protected-change-consumer
go test -run '^ExampleSQLiteChangeStore$' -v ./examples/protected-change-consumer
```

These commands need no account, external credentials, Redis server, or hardware.
They create temporary private databases and synthetic keys, certificates, trust
sources, and verifier nonces. The integration recipe runs both attested and
software-only verification over actual mTLS 1.3 connections. It:

1. Commits a setting change and its receipt in one SQLite transaction.
2. Injects a lost database acknowledgement, or drops the HTTP response after
   commit. The caller cannot infer failure from either condition.
3. Rejects reuse of the original proof without dispatching the change again.
4. Closes and reopens the database.
5. Uses a new TLS-bound `change.read` proof to recover the `APPLIED` receipt.

The tests also reject missing proofs, replayed read proofs, changed tenants and
values, read proofs sent to the mutation endpoint, and write proofs sent to the
read endpoint. A failure injected between receipt insertion and the local
setting update rolls back both writes. Concurrent handles converge on one
receipt, and conflicting actions or identities cannot replace it.

## Wire the application

`MemoryChangeStore` remains the small in-memory test/reference store.
`SQLiteChangeStore` provides a durable example for a **local setting whose effect
and receipt can share one database transaction**. It is not an adapter for
remote APIs or a claim of production deployment qualification.

Create an owner-only data directory first. Pass an absolute, clean database
path to `OpenSQLiteChangeStore`; symlink database files and symlink immediate
parent directories are rejected. Unix parent/file permissions must be private
(0700/0600). On Windows, the caller must establish an owner-only directory ACL;
the example does not validate Windows ACLs. Keep the directory trusted for the
entire process lifetime and use a local filesystem.

With operator-configured authorities, replay storage and nonce sources:

```go
store, err := protectedchange.OpenSQLiteChangeStore(ctx, databasePath)
if err != nil {
    return err
}
defer store.Close()

apply := protectedchange.Application{
    SoftwareProfile: &softwareProfile,
    Nonces:          mutationNonces,
    Store:           store,
    ExpectedAgent:   expectedAgent,
    AuditFailure:    privateAudit,
}
lookupVerifier := apply
lookupVerifier.Nonces = outcomeNonces

mux := http.NewServeMux()
mux.Handle(protectedchange.ChangePath, apply)
mux.Handle(protectedchange.OutcomePath, protectedchange.OutcomeApplication{
    Verifier: lookupVerifier,
    Store:    store,
})
```

Use `Profile` instead of `SoftwareProfile` for an attested deployment; configure
one composition explicitly. Install this mux on an HTTPS server that requires
and verifies client certificates and TLS 1.3. The handlers derive bindings from
the accepted connection and do not trust proxy-supplied identity headers.
Retain the independent ASB replay store and this application database across
restarts. A database receipt does not replace replay protection.

The variables above are deployment inputs, not automatically provisioned keys
or authorities. The reference nonce map, local replay map, fixed timestamps,
and signing helpers in `e2e_test.go` are test fixtures. For sender wiring, read
`actionHeaders` and `exchangeRecoveryRequest` in the tests: establish mTLS,
derive the appropriate canonical context and live TLS exporter binding, obtain
the grant and sign the session proof, then send that exact body on **that same
connection**. The test helper is not a reusable production HTTP client.

## Recover an unknown result

`POST /v1/changes` retains the original change schema. Success is 204. A
definite identifier/identity conflict is 409. An application-store failure is
503 with `{"code":"OUTCOME_UNKNOWN","retryable":false}` because the commit
may already have completed. Nonce-source outages are 503, while a missing
verifier nonce is 401. Backend errors go to `AuditFailure` for private diagnosis;
raw backend errors, tokens and identity details are not returned to the caller.

After a timeout, lost response or `OUTCOME_UNKNOWN`:

1. Preserve the original `change_id`, tenant, setting and enabled value.
2. Request a fresh verifier-issued outcome nonce and a Manager grant for
   `ExpectedOutcomePolicy(change, agent)`. Its intent is
   `change:intent:outcome`, capability is `change:capability:read`, scope is
   `change.read`, and authorization detail is `change:read-outcome`. It must
   retain the original issuer, Actor, task and delegation attribution.
3. On the accepted TLS connection derive `CanonicalOutcomeContext(change)` and
   the appropriate ASB binding, sign a fresh session proof, and POST the full
   original change body to `/v1/changes/outcome` with the usual ASB headers.
   This proof is distinct from a mutation proof and is itself one-shot.
4. `{"state":"APPLIED"}` confirms the historical local commit; it does not
   claim that no later authorized change updated the current setting.
   `{"state":"NOT_RECORDED"}` only means no matching receipt was visible.
   It does **not** authorize redispatch: an original request can still be
   in flight. Fence or finish the original worker and perform operator-owned
   reconciliation before obtaining any new mutation authorization.

Only a fresh authenticated read can reach the outcome store. A stored receipt
must match the full original change and issuer, Actor, task and delegation;
otherwise the endpoint returns 404 without the receipt. Responses use
`Cache-Control: no-store` and never include stored identity details.

This recipe does not resolve external provider effects, database rollback,
backup freshness, multi-host HA, or loss of the replay database. Keep those
deployment responsibilities separate from the tested local transaction.
