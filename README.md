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
  and credential-to-target relationships, never provider metadata or bearer
  values
- the agenix recipient map (`secrets.nix`) — which public keys may decrypt which
  `.age` file
- the encrypted secret blobs (`secrets/**.age`) — forge tokens, the forge git key,
  and per-VM SSH host keys
- public-key registries (`machine-host-keys.json`, `forge-ssh-keys.json`,
  `keys/*.pub`)
- the Forgejo HTTPS-token deployment map (`forgejo-token-groups.json`)
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
| `lib.devIdentities` | attrs | per-dev-VM identity: forge user, SSH key name, forge/agent token file paths, GPG signing key |
| `lib.privacyIdentities` | attrs | per-privacy-VM identity (username only) |
| `lib.nexusIdentity` | attrs | host identity: hostname, host SSH public keys, forge coordinates |
| `lib.vmUsernames` | attrs | machine name -> login username |
| `lib.credentials` | attrs | credential inventory keyed by name; each entry has `kind`, `owner`, `public_key`, `consumers`, `rotation_state` |
| `lib.forgeSshKeys` | attrs | forge git SSH key registry (from `forge-ssh-keys.json`) |
| `lib.forgejoTokenGroups` | attrs | Forgejo HTTPS-token deployment map (from `forgejo-token-groups.json`) |
| `lib.machineHostKeys` | attrs | per-machine SSH host public keys, active + staged (from `machine-host-keys.json`) |
| `lib.vmHostKeySecretFiles` | attrs | machine name -> path of its `*-ssh.age` host-key secret, derived by scanning `secrets/vm-host-keys/` |
| `lib.githubCredentialTargets` | attrs | per-machine GitHub credential targets — empty in the template |
| `lib.piCredentials` | attrs | validated `pi-credentials.json`, keyed by credential ID |
| `lib.piCredentialCiphertextPaths` | attrs | credential ID -> derived `secrets/pi-credentials/<id>.age` path |
| `lib.piProviderCredentials` | attrs | provider ID -> credential ID, derived from the registry |
| `lib.piCredentialInventory` | attrs | credential-inventory entries derived for Pi ciphertexts |
| `lib.piCredentialRecipients` | attrs | relative Pi ciphertext path -> `{ publicKeys = [...] }` |
| `lib.piCredentialProjections` | attrs | dev VM -> `{ credentials; providers; }` projection |
| `lib.validatePiProviderReferences` | function | rejects provider IDs absent from a caller-supplied known-ID list and returns the provider-to-credential projection |
| `lib.mkPiCredentialContract` | function | validates and derives the same contract from caller-supplied data |
| `lib.consumedInventorySource` | flake input | exact inventory source consumed while validating targets |
| `checks.<platform>.credential-inventory` | derivation | validates inventory schema, recipient resolution, key/secret file presence, and rotation invariants |
| `checks.<platform>.pi-credential-registry` | derivation | validates the empty public contract plus synthetic schema, target, recipient, ciphertext, projection, and provider-reference sabotage |
| `checks.<platform>.external-ssh-trust-targets` | derivation | validates the external SSH trust-target schema against `identity.sshHosts` |

`checks` are generated for every platform in `inventory.lib.supportedPlatforms`.
The only flake inputs are `nixpkgs` (nixos-25.11) and `inventory`.

The secrets contract deliberately does not import profiles. It validates Pi
credential IDs, targets, recipient keys, ciphertext presence, and the rule that
one provider belongs to only one credential. The framework joins this contract
to `profiles.lib.piProviders` and must force
`validatePiProviderReferences (builtins.attrNames profiles.lib.piProviders)` so
unknown providers fail at the consumption seam without creating another flake
input edge here.

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
- Recipient lists pull the **active** host key plus any **staged** key from
  `machine-host-keys.json`, so a key rotation can encrypt to both the old and new
  recipient during the overlap.
- A declared Pi credential is encrypted to the active/staged Nexus key and the
  active/staged keys of every target VM. Its path is always derived as
  `secrets/pi-credentials/<credential>.age`; the registry never repeats it.

All `.age` files are age-encrypted blobs (`age-encryption.org/v1`); this repo
stores ciphertext only. Public keys and recipient metadata are public by nature.

## Layout

```
flake.nix                     inputs (nixpkgs, inventory); lib / checks outputs
identity.nix                  synthetic identity, VM rosters, SSH host aliases, trust targets
credentials.nix               credential inventory derived from the key registries + token entries
pi-credentials.json           Pi credential -> providers/targets/rotation strategy; empty in the public template
secrets.nix                   agenix recipient map (.age path -> recipient public keys)
lib/pi-credential-contract.nix validates and derives Pi credential projections
lib/pi-credential-recipients.nix standalone recipient generator used by agenix
machine-host-keys.json        per-machine SSH host public keys (active/staged)
forge-ssh-keys.json           forge git SSH key registry
forgejo-token-groups.json     Forgejo HTTPS-token deployment + local-auth-refresh map
keys/
  allod_vm.pub                forge git SSH public key (checked against the registry)
secrets/
  *.age                       encrypted forge tokens and forge git key
  vm-host-keys/*.age          encrypted per-VM SSH host keys
  pi-credentials/*.age        private-fork Pi credential ciphertexts; absent from the empty public template
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
- `machineHostKeys` / `vmHostKeySecretFiles` supply VM host-key facts and agenix
  host-key paths.
- `credentials` / `forgeSshKeys` / `forgejoTokenGroups` / `githubCredentialTargets`
  drive token and forge-key deployment; `age.secrets` files are read straight from
  `${secrets}/<secret path>`.
- `piCredentials`, `piProviderCredentials`, and `piCredentialProjections` expose
  the validated Pi credential contract. Each `devIdentities.<vm>` also carries
  only that VM's `piCredentials` and `piProviders` projection.
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
