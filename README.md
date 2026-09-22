# secrets

Consumer-owned identity, credential inventory, encrypted secrets, and git policy
data for the Allod VM stack. This is the **public template**: every value here is
synthetic (RFC 5737 documentation IPs, `example.com` addresses, throwaway keys) so
the framework repos have something to build and check against. A real deployment
replaces this flake with a private fork carrying the operator's actual identities,
recipients, and `.age` blobs.

Allod splits by ownership: framework repos (`vm`, `archetypes`, `nexus`, `tools`)
describe *how* the system works; this repo, alongside `inventory`, decides *what*
exists. Secrets are encrypted with age/agenix — a single host identity key
decrypts everything, and each VM's SSH host key is an age recipient for the
secrets that VM needs at runtime.

## Owns / does not own

This repo owns:

- the identity template (`identity.nix`) — synthetic operator/agent identity, VM
  rosters, SSH client host aliases, external SSH trust targets
- the credential inventory (`credentials.nix`) — recipient metadata: owner, kind,
  rotation state, and consumers for every key and token; Pi service entries are
  derived from `pi-credentials.json`
- the Pi credential registry (`pi-credentials.json`) — credential-to-provider
  and credential-to-target relationships plus each credential's named tokens and
  deployment default, never provider metadata or bearer values
- the agenix recipient map (`secrets.nix`) — which public keys may decrypt which
  `.age` file
- the encrypted secret blobs (`secrets/**.age`) — forge tokens, the forge git key,
  and per-VM SSH host keys
- public-key registries (`machine-host-keys.json`, `forge-ssh-keys.json`,
  `keys/*.pub`)
- the credential rotation registry (`rotation-registry.json`)
- the credential-store URL grammar and its accept/reject vectors
  (`credential-store-url.json`) — the table allod/archetypes, allod/nexus, and
  allod/tools are meant to read; each cutover lands in its own repo
- git policy data (`git/*`) — branch-protection, signing, PR-branch, and
  external-remote allowlists
- flake `checks` that keep all of the above internally consistent

This repo does **not** own:

- framework NixOS/Home Manager modules or the agenix app re-export (`vm`)
- the archetype framework, builders, and profile assembly (`archetypes`)
- machine profile definitions — which modules compose each machine (`profiles`)
- VM specs, the platform list, and the roster of record (`inventory`)
- host NixOS config and provisioning scripts (`nexus`)
- the git-hook scripts that *enforce* the git policy data (`tools`) — this repo
  ships only the data

## Exported outputs

| Output | Type | Description |
|---|---|---|
| `lib.identity` | attrs | raw `identity.nix` — username, email, forge host/port/user, host public key(s), VM rosters, SSH host aliases, external SSH trust targets |
| `lib.devIdentities` | attrs | per-dev-VM identity: forge user, SSH key name, forge/agent token file paths, GPG signing key, `sshHosts` (the VM's own external SSH aliases, defaulted) |
| `lib.privacyIdentities` | attrs | per-privacy-VM identity (username only) |
| `lib.nexusIdentity` | attrs | host identity: hostname, host SSH public keys, forge coordinates, `userForgejoTokenFile` / `siteHostingConfigFile` (null, or a Nix path to an `.age` file) |
| `lib.vmUsernames` | attrs | machine name -> login username |
| `lib.credentials` | attrs | credential inventory keyed by name; each entry has `kind`, `owner`, `public_key`, `consumers`, `rotation_state` (`pending`, `active`, `staged`, `retiring`, or `retired`) |
| `lib.forgeSshKeys` | attrs | forge git SSH key registry (from `forge-ssh-keys.json`) |
| `lib.rotationRegistry` | attrs | credential rotation registry, including each credential's rendered-value template and verification commands (from `rotation-registry.json`); validated on read, so a malformed registry fails every consumer |
| `lib.credentialStoreUrl` | attrs | the credential-store URL grammar as data (from `credential-store-url.json`): `line`, `blank_line`, and the `vectors` table each consumer's tests are meant to read |
| `lib.isCredentialStoreUrlTemplate` | function | the grammar half alone: true when a credential declares exactly one credential-store URL line, whatever `format` it carries. A consumer with its own `format` policy composes this one rather than respelling the grammar |
| `lib.isCredentialStoreUrlSource` | function | that grammar plus this registry's own `format` policy — a credential carrying `format` is refused — the predicate `refresh-local-auth` and the archetypes checks are to consume instead of redefining |
| `lib.localAuthRefreshDiagnostics` | function | plain-English problems with a registry's `local_auth_refresh` entries, empty when there are none |
| `lib.mkLocalAuthRefreshSources` | function | the same validated projection as a function of a caller-supplied registry: asserts `lib.localAuthRefreshDiagnostics` is empty, then projects; `lib.localAuthRefreshSources` is this applied to `rotation-registry.json`, and a fork applies it to its own registry instead of re-spelling the mapping |
| `lib.localAuthRefreshSources` | attrs | group alias -> list of `{ contract; system; local_username; source_credential; secret_path; }`, validated on read so a consumer never re-derives the URL grammar |
| `lib.credentialEncodings` | list of strings | supported credential value encoders; currently `rclone-obscure` |
| `lib.machineHostKeys` | attrs | per-VM SSH host public keys, active + staged (from `machine-host-keys.json`) |
| `lib.vmHostKeySecretFiles` | attrs | machine name -> path of its `*-ssh.age` host-key secret, derived by scanning `secrets/vm-host-keys/` |
| `lib.githubCredentialTargets` | attrs | per-machine GitHub credential targets — empty in the template |
| `lib.piCredentials` | attrs | validated `pi-credentials.json`, keyed by credential ID |
| `lib.piCredentialCiphertextPaths` | attrs | credential ID -> token name -> derived `secrets/pi-credentials/<id>/<token>.age` path |
| `lib.piProviderCredentials` | attrs | provider ID -> credential ID, derived from the registry |
| `lib.piCredentialInventory` | attrs | credential-inventory entries derived for Pi ciphertexts, one consumer record per token ciphertext |
| `lib.piCredentialRecipients` | attrs | relative Pi ciphertext path -> `{ publicKeys = [...] }`, ordered from hypervisor identity keys then target VM keys |
| `lib.piCredentialProjections` | attrs | dev VM -> `{ credentials; providers; }` projection |
| `lib.validatePiProviderReferences` | function | rejects provider IDs absent from a caller-supplied known-ID list and returns the provider-to-credential projection |
| `lib.mkPiCredentialContract` | function | validates and derives the same contract from caller-supplied data; accepts explicit ordered `hypervisorPublicKeys`, while `nexusName` is required only for the legacy machine-key fallback |
| `lib.projectDevSshHosts` | function | projects one dev VM's `devVMs.<vm>.sshHosts` onto its defaulted alias set, refusing a reserved name, a non-literal alias, two aliases differing only by case, a malformed entry, and anything that would open a second `ssh_config` block (an `extraOptions` `header` or non-bare-directive key, a newline in any string field); the framework and downstream forks call it rather than respelling the rules |
| `lib.consumedInventorySource` | flake input | exact inventory source consumed while validating targets |
| `checks.<platform>.credential-inventory` | derivation | validates inventory schema, recipient resolution, key/secret file presence, and rotation invariants |
| `checks.<platform>.credential-registry` | derivation | validates the public credential rotation registry plus a positive value-template fixture and one sabotage witness per template/verification validator |
| `checks.<platform>.credential-store-url` | derivation | asserts `lib.isCredentialStoreUrlSource` agrees with every vector in `credential-store-url.json`, naming any that disagrees, and that `lib.isCredentialStoreUrlTemplate` agrees on every vector carrying no `format` |
| `checks.<platform>.local-auth-refresh` | derivation | forces the public registry's refresh projection and runs one sabotage registry per `local_auth_refresh` validator, pinning each by its diagnostic |
| `checks.<platform>.pi-credential-registry` | derivation | validates the empty public contract plus synthetic schema, target, token, default, recipient, ciphertext, projection, and provider-reference sabotage |
| `checks.<platform>.external-ssh-trust-targets` | derivation | validates the external SSH trust-target schema against `identity.sshHosts` |
| `checks.<platform>.dev-ssh-hosts` | derivation | validates the per-dev-VM external SSH alias projection: a machine without `sshHosts` projects empty, an entry gains its VM's own key and `identitiesOnly` while keeping its own fields, and one sabotage witness per refusal (reserved name, non-literal alias, two aliases differing only by case, malformed entry, an `extraOptions` key that is not a bare directive, a newline inside any string field) |

`checks` are generated for every platform in `inventory.lib.supportedPlatforms`.
The only flake inputs are `nixpkgs` (nixos-25.11) and `inventory`.

## Checks

The check suite lives under `checks/`, one file per check, and `checks/default.nix` is the index that hands each check its arguments. `flake.nix` passes that index the composition — `pkgs`, the identity and credential data, and the validators `lib/` exposes over them — and a check's own argument list is the whole of what it reads. Adding a check is a new file and one entry in the index. Its derivation name is what a fork excludes or re-exports by, so it stays unique and does not change when a check moves.

The registry validators a fork's own data must satisfy — `credentialRegistryDiagnostics` / `validateCredentialRegistry`, the credential-store-URL predicates, and the local-auth-refresh contract and diagnostics — live in `lib/` beside `lib/dev-ssh-hosts.nix` and the Pi credential contract files, not in `flake.nix`; each takes the data it validates as an argument rather than closing over it.

The secrets contract deliberately does not import profiles. It validates Pi
credential IDs, targets, token names, deployment defaults, recipient keys,
ciphertext presence, and the rule that one provider belongs to only one
credential. The framework joins this contract
to `profiles.lib.piProviders` and must force
`validatePiProviderReferences (builtins.attrNames profiles.lib.piProviders)` so
unknown providers fail at the consumption seam without creating another flake
input edge here.

## Credential rotation registry schema

`rotation-registry.json` declares the non-secret text around a credential and
the command that verifies each deployed target. `service` names the
credential's issuer, `forgejo` for a Forgejo UI token or `none` for anything
else; the check does not validate it, `allod secret` refuses any other
value. A new credential omits `value` when its plaintext is the secret
itself; otherwise `value.template` contains exactly one literal `{secret}`.
`value.encode`, when present, must be exported by `lib.credentialEncodings`;
it transforms the secret before substitution. The template is otherwise
byte-preserving, including trailing newlines. `value` holds only `template`
and `encode`; any other field fails the check.

The public example is a new-shape credential:

```json
{
  "credential": "forgejo-https-token-allod-dev",
  "secret_path": "secrets/forgejo-https-token-allod-dev.age",
  "value": { "template": "https://allod-agent:{secret}@forge.anarch.diy" },
  "targets": [
    {
      "system": "allod-dev",
      "deployed_path": "/root/.git-credentials",
      "verify": "sudo env HOME=/root GIT_TERMINAL_PROMPT=0 git ls-remote https://forge.anarch.diy/allod/tools.git HEAD"
    }
  ]
}
```

Every new-shape target has a one-line `verify` command that is not empty and
not only whitespace; consumers print it verbatim, prefixing a remote target
with SSH. Every credential declares at least one target and every group at
least one credential. Typical commands replace the former probe names directly:

```sh
sudo -u allod forge token verify
git ls-remote https://forge.anarch.diy/allod/tools.git HEAD
rclone lsd shared:
tailscale status
```

A credential carrying the retired `format` field, or a target whose `verify`
is not a string, fails the check. Existing group metadata, including
`local_auth_refresh`, remains structured and unchanged; the registry check
requires only the group `credentials` list for this contract. Credentials in
one group must agree on `value.encode`, because one prompted value serves
that group.

## Pi credential registry schema

Each `pi-credentials.json` record has exactly four fields — anything else,
including a legacy `rotationStrategy`, fails evaluation:

```json
{
  "<credential>": {
    "providers": ["<provider-id>"],
    "targets": ["<dev-vm>"],
    "tokens": ["<token-name>"],
    "defaultToken": "<token-name>"
  }
}
```

`providers` and `targets` are non-empty unique ID lists (`^[a-z0-9][a-z0-9-]*$`);
a provider belongs to exactly one credential and every target must be a libvirt
dev VM with an identity. `tokens` is a non-empty unique list of opaque token
names (`^[a-z][a-z0-9-]{0,62}$`, excluding the reserved `none` pi-provider
token-default clearing word — a different namespace and a different pattern
from provider IDs). `defaultToken` is `null` or one of the listed names. The
public template ships `{}`, which is valid and generates nothing.

## Age recipient model

`secrets.nix` is the agenix recipient config: it maps each `.age` path to the list
of SSH public keys allowed to decrypt it.

- The **host identity key** (the `nexus` SSH host key) is a recipient of *every*
  secret — one key decrypts the whole store.
- **Per-VM runtime secrets** (forge HTTPS token, agent PR token, forge git key) are
  additionally encrypted to the owning VM's host key(s), so the running VM can
  decrypt them via agenix on boot.
- **VM SSH host-key secrets** (`secrets/vm-host-keys/*-ssh.age`) are encrypted to
  the host key only; `nexus` injects the decrypted host key into a VM at provision
  time (before first boot) so agenix can then unlock that VM's other secrets.
- Recipient lists pull the hypervisor's **active** host key plus any **staged**
  key from `identity.hostPublicKeys`, and target VM keys from
  `machine-host-keys.json`, so a key rotation can encrypt to both old and new
  recipients during the overlap.
- A declared Pi credential holds one or more named tokens, and each token is a
  separate ciphertext encrypted to the active/staged Nexus key plus the
  active/staged keys of every target VM — one recipient set per credential,
  shared by all of its tokens. Each path is always derived as
  `secrets/pi-credentials/<credential>/<token>.age`; the registry never repeats
  it.

All `.age` files are age-encrypted blobs (`age-encryption.org/v1`); this repo
stores ciphertext only. Public keys and recipient metadata are public by nature.

## Layout

```
flake.nix                     inputs (nixpkgs, inventory); composes data + lib/checks outputs
identity.nix                  synthetic identity, VM rosters, SSH host aliases, trust targets
credentials.nix               credential inventory derived from the key registries + token entries
pi-credentials.json           Pi credential -> providers/targets/tokens/defaultToken; empty in the public template
secrets.nix                   agenix recipient map (.age path -> recipient public keys)
checks/default.nix            the check suite index; hands each check file its inputs
checks/*.nix                  one file per check (see "Checks" below)
lib/credential-registry.nix   registry-shape validation (`credentialRegistryDiagnostics`, `validateCredentialRegistry`)
lib/credential-store-url.nix  the credential-store URL grammar/policy predicates
lib/local-auth-refresh.nix    the local-auth-refresh contract, diagnostics, and projection
lib/dev-ssh-hosts.nix         projects a dev VM's own external SSH aliases
lib/pi-credential-contract.nix validates and derives Pi credential projections
lib/pi-credential-recipients.nix standalone recipient generator used by agenix
lib/pi-credential-schema.nix shared strict schema for flake and standalone agenix paths
machine-host-keys.json        per-VM SSH host public keys (active/staged)
forge-ssh-keys.json           forge git SSH key registry
rotation-registry.json        credential rotation registry: rendered-value templates, verification commands, and local-auth-refresh map
credential-store-url.json     credential-store URL grammar plus the shared accept/reject vector table
keys/
  allod_vm.pub                forge git SSH public key (checked against the registry)
secrets/
  *.age                       encrypted forge tokens and forge git key; in a
                              deployment, also the ciphertexts named by
                              userForgejoTokenFile and siteHostingConfigFile,
                              which the hypervisor places at
                              /home/<user>/.config/git/forgejo-token and
                              /home/<user>/.config/rclone/rclone.conf, mode 0600 each
  vm-host-keys/*.age          encrypted per-VM SSH host keys
  pi-credentials/<credential>/<token>.age
                              private-fork Pi credential ciphertexts, one per named token;
                              absent from the empty public template
git/                          git policy data installed to ~/.config/git on VMs
  protected-branches          repo/branch pairs where direct commits are blocked
  signing-required-branches   branches requiring GPG-signed commits
  active-pr-branches          remote branches requiring GPG-signed pushes
  allowed-external-remotes    remotes permitted for push (forge.anarch.diy always allowed)
```

## How `archetypes` consumes it

`archetypes` pins this repo as its `secrets` flake input and reads almost every
output:

- `devIdentities` / `privacyIdentities` / `nexusIdentity` / `vmUsernames` drive
  per-machine users and forge identity.
- `nexusIdentity.sshPublicKeys` supplies ordered hypervisor recipients;
  `machineHostKeys` / `vmHostKeySecretFiles` supply VM host-key facts and agenix
  host-key paths.
- `nexusIdentity.userForgejoTokenFile` / `siteHostingConfigFile` are read by the
  hypervisor builder (allod/archetypes#74) with `or null`, so either side can
  land first. When non-null, each drives an `age.secrets` entry that places the
  host user's Forgejo token or site hosting rclone config in that user's home
  directory; null means the file is absent and no agenix activation runs for
  it. Each value is a Nix path, never a string, the same form the dev-VM token
  fields take. The shape:

  | Field | Decrypts to | Recipients | Placed at |
  | --- | --- | --- | --- |
  | `userForgejoTokenFile` | the raw Forgejo API token of the human account | hypervisor host keys only | `/home/<user>/.config/git/forgejo-token`, mode 0600 |
  | `siteHostingConfigFile` | one complete rclone stanza: `[shared]`, `type = ftp`, `host`, `user`, `pass` in rclone's obscured form, `explicit_tls = true` | hypervisor host keys only | `/home/<user>/.config/rclone/rclone.conf`, mode 0600 |

  The rclone stanza is stored whole, not as a bare password: rclone reads its
  config file and nothing else, so storing exactly what it reads means no
  activation step reshapes a secret. Obscuring is reversible by anyone with
  rclone, so the stanza is as sensitive as the password underneath it — that is
  why the recipient set is the host alone, not the full VM fleet.

  Each non-null file needs a `credentials.nix` entry shaped like the existing
  `agent-pr-token` one (`name`, `kind`, `owner`, `public_key = null`,
  `consumers`, `rotation_state`) whose consumer is
  `{ type = "agenix"; repo = "secrets"; secret = "secrets/<name>.age"; }`, plus a
  matching `secrets.nix` recipient line; `credential-inventory` refuses an age
  file with no record and a record with no file. The public template commits no
  new ciphertext for either field, because both are null.

  A credential lands in two halves with different authors. An agent's PR
  carries the non-secret half — the `credentials.nix` entry with
  `rotation_state = "pending"`, the `secrets.nix` line, and the rotation
  registry entry — and is green on its own: `credential-inventory` requires
  the age file to be *absent* while the entry is `pending`. The host operator
  then runs `allod secret create <name>` on that branch, which encrypts the
  value to the recipients `secrets.nix` declares, writes the file, and flips
  the state to `active`, where the check requires the file present. A
  `pending` entry with a file, or an `active` one without, fails the check.
- `credentials` / `forgeSshKeys` / `rotationRegistry` / `githubCredentialTargets`
  drive token and forge-key deployment; `age.secrets` files are read straight from
  `${secrets}/<secret path>`.
- `piCredentials`, `piProviderCredentials`, and `piCredentialProjections` expose
  the validated Pi credential contract. Each `devIdentities.<vm>` also carries
  only that VM's `piCredentials` and `piProviders` projection. A projected
  credential is `{ providers = [ ... ]; tokens.<token>.file = <ciphertext path>;
  defaultToken = null | "<token>"; }` — names and paths only, never endpoint
  metadata or a bearer value.
- `gitPolicySource` defaults to this flake, so `git/*` is symlinked into
  `~/.config/git/` on every dev VM and enforced by the `protected-refs-policy` hook
  from `tools`.

## Related repos

- `inventory` — VM specs, platform list, and the roster of record (the other half
  of the consumer-owned "what")
- `archetypes` — the VM framework; pins this flake as its `secrets` input and is its primary consumer
- `profiles` — machine profile definitions (does not import this flake)
- `vm` — framework NixOS/Home Manager modules and the agenix app re-export
- `nexus` — host config and provisioning; injects VM host keys so agenix can
  decrypt on first boot
- `tools` — `protected-refs-policy` and other hooks that enforce the git policy
  data shipped here

## Cloning

    git clone https://forge.anarch.diy/allod/secrets.git
