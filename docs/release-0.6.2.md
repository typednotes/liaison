# Liaison v0.6.2

Includes the GitHub User-Agent fix from v0.6.1 and the shared bounded main-CI wait
used by all Typednotes versioned publishers. The v0.6.1 tag stays immutable and
retains its original immediate-check workflow.

From the broker repository, the user may now publish the branch and tag together:

```sh
git push origin main v0.6.2
```

The verification job polls the latest exact-commit push-to-main CI run every
15 seconds, for up to two hours. Missing/queued/running evidence is awaited;
failed or cancelled CI, invalid identity/status/schema, API errors and timeout
refuse publication. PR/manual-only results cannot replace successful main CI.
The read-only verification job checks tag/checkout equality and main ancestry;
only the subsequent verified-SHA publisher receives registry write access.

The full main CI is attested, not rerun on tags. Versioned Docker publication,
semver aliases and stable `latest` retain their existing semantics. No runtime
contract, dependency pin or SQL migration changes from v0.6.1.

The shared gate and test scripts are byte-identical across all eight publishing
repositories. 400 offline cases (50 per copy) exercise registration/queue/run
transitions, latest-attempt denials, metadata tampering while waiting, API failures,
real bounded timeout, invalid wait/poll bounds and tag/ref identity. The original
GitHub fix also passes the Lean suite, 655 broker HTTP cases and app/broker tests.

Wait for **Lean Action CI** and **Publish Docker image** to succeed, then run the
reviewed `typednotes-infra` Apply. Its `latest` selector adopts the new broker
digest. Test the existing GitHub connection afterward. An infra Apply before
the new image is published still deploys the previous broker.
