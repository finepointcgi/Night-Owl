# Manifest signing key

Night Owl installs only accept engine manifests signed by one key. The **public** half is committed
(`keys/nightowl-signing.pub`) and compiled into every release binary. The **private** half signs each
manifest in the `engines-release` workflow.

## Where the private key lives

| Copy | Purpose |
|------|---------|
| GitHub Actions secret `NIGHTOWL_SIGNING_KEY` | Used by `engines-release`. GitHub never shows it again after it is set. |
| A copy you keep offline (password manager, encrypted drive) | Recovery. **Keep one outside GitHub.** |

Never commit it. `nightowl manifest keygen <dir>` refuses to overwrite an existing key.

## If the key is lost

The client trusts exactly one embedded key and has no rotation mechanism yet, so a lost key cannot be
replaced from the server side:

1. Generate a new pair: `nightowl manifest keygen ./new-key`.
2. Commit the new `keys/nightowl-signing.pub`, set the new secret, tag a new release (the binary embeds the new key).
3. Existing installs reject manifests signed by the new key and keep running the last manifest they have.
   Their `self-update` cannot help either, because the update entry lives inside the (now unverifiable) manifest.
   Users must reinstall once with `scripts/install.sh`.

## If the key is leaked

Treat it as lost, and act quickly: whoever holds it can publish a manifest that pins engine images of
their choosing to every install. Rotate as above, delete the old secret, and say so in the release notes.

## Known gap

Trusting a list of keys (current plus next) would make rotation seamless: ship the next public key one
release ahead, then switch signing. See `docs/BACKLOG.md`.
