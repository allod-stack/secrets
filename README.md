# secrets

Consumer-owned identity, credential inventory, encrypted secrets, and git policy
data for the Allod VM stack. This is the **public template**: every value here is
synthetic (RFC 5737 documentation IPs, `example.com` addresses, throwaway keys) so
the framework repos have something to build and check against. A real deployment
replaces this flake with a private fork carrying the operator's actual identities,
recipients, and `.age` blobs.

Allod splits by ownership: framework repos (`vm`, `profiles`, `nexus`, `tools`)
describe *how* the system works; this repo, alongside `inventory`, decides *what*
exists. Secrets are encrypted with age/agenix — a single host identity key
decrypts everything, and each VM's SSH host key is an age recipient for the
secrets that VM needs at runtime.

## Owns / does not own

This repo owns:

- the identity template (`identity.nix`) — synthetic operator/agent identity, VM
  rosters, SSH client host aliases, external SSH trust targets
- the credential inventory (`credentials.nix`) — recipient metadata: owner, kind,
  rotation state, and consumers for every key and token
- the agenix recipient map (`secrets.nix`) — which public keys may decrypt which
  `.age` file
- the encrypted secret blobs (`secrets/**.age`) — forge tokens, the forge git key,
  and per-VM SSH host keys
- public-key registries (`machine-host-keys.json`, `forge-ssh-keys.json`,
  `keys/*.pub`)
- the Forgejo HTTPS-token deployment map (`forgejo-token-groups.json`)
- git policy data (`git/*`) — branch-protection, signing, PR-branch, and
  external-remote allowlists
- a consumer preferences Home Manager module (`modules/preferences.nix`)
- flake `checks` that keep all of the above internally consistent

This repo does **not** own:

- framework NixOS/Home Manager modules or the agenix app re-export (`vm`)
- per-VM system configs and profile assembly (`profiles`)
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
| `lib.profileDefinitions` | attrs | consumer profile-definition overlay — empty in the template |
| `lib.profileData` | attrs | per-machine profile data — empty in the template |
| `lib.githubCredentialTargets` | attrs | per-machine GitHub credential targets — empty in the template |
| `homeModules.preferences` | HM module | consumer editor/shell preferences (nvim default editor, bash `codex` alias, `GIT_TERMINAL_PROMPT`) |
| `checks.<platform>.credential-inventory` | derivation | validates inventory schema, recipient resolution, key/secret file presence, and rotation invariants |
| `checks.<platform>.external-ssh-trust-targets` | derivation | validates the external SSH trust-target schema against `identity.sshHosts` |

`checks` are generated for every platform in `inventory.lib.supportedPlatforms`.
The only flake inputs are `nixpkgs` (nixos-25.11) and `inventory`.

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

All `.age` files are age-encrypted blobs (`age-encryption.org/v1`); this repo
stores ciphertext only. Public keys and recipient metadata are public by nature.

## Layout

```
flake.nix                     inputs (nixpkgs, inventory); lib / homeModules / checks outputs
identity.nix                  synthetic identity, VM rosters, SSH host aliases, trust targets
credentials.nix               credential inventory derived from the key registries + token entries
secrets.nix                   agenix recipient map (.age path -> recipient public keys)
machine-host-keys.json        per-machine SSH host public keys (active/staged)
forge-ssh-keys.json           forge git SSH key registry
forgejo-token-groups.json     Forgejo HTTPS-token deployment + local-auth-refresh map
keys/
  allod_vm.pub                forge git SSH public key (checked against the registry)
secrets/
  *.age                       encrypted forge tokens and forge git key
  vm-host-keys/*.age          encrypted per-VM SSH host keys
git/                          git policy data installed to ~/.config/git on VMs
  protected-branches          repo/branch pairs where direct commits are blocked
  signing-required-branches   branches requiring GPG-signed commits
  active-pr-branches          remote branches requiring GPG-signed pushes
  allowed-external-remotes    remotes permitted for push (forge.anarch.diy always allowed)
modules/
  preferences.nix             consumer preferences Home Manager module
```

## How `profiles` consumes it

`profiles` pins this repo as its `secrets` flake input and reads almost every
output:

- `devIdentities` / `privacyIdentities` / `nexusIdentity` / `vmUsernames` drive
  per-machine users and forge identity.
- `machineHostKeys` / `vmHostKeySecretFiles` supply VM host-key facts and agenix
  host-key paths.
- `credentials` / `forgeSshKeys` / `forgejoTokenGroups` / `githubCredentialTargets`
  drive token and forge-key deployment; `age.secrets` files are read straight from
  `${secrets}/<secret path>`.
- `homeModules.preferences` is layered into each VM's Home Manager config.
- `gitPolicySource` defaults to this flake, so `git/*` is symlinked into
  `~/.config/git/` on every dev VM and enforced by the `protected-refs-policy` hook
  from `tools`.

## Related repos

- `inventory` — VM specs, platform list, and the roster of record (the other half
  of the consumer-owned "what")
- `profiles` — per-VM NixOS configs; the primary consumer of this flake
- `vm` — framework NixOS/Home Manager modules and the agenix app re-export
- `nexus` — host config and provisioning; injects VM host keys so agenix can
  decrypt on first boot
- `tools` — `protected-refs-policy` and other hooks that enforce the git policy
  data shipped here

## Cloning

    git clone https://forge.anarch.diy/allod/secrets.git
