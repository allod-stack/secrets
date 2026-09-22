{ lib, pkgs, credentialRegistryDiagnostics, validateCredentialRegistry }:
  let
    current = builtins.fromJSON (builtins.readFile ../rotation-registry.json);

    newPlainCredential = {
      credential = "new-plain-token";
      secret_path = "secrets/new-plain-token.age";
      targets = [{
        system = "fixture-host";
        verify = "test -n \"$TOKEN\"";
      }];
    };
    encodedCredential = {
      credential = "new-encoded-password";
      secret_path = "secrets/new-encoded-password.age";
      value = {
        template = "[shared]\ntype = ftp\npass = {secret}\n";
        encode = "rclone-obscure";
      };
      targets = [{
        system = "fixture-host";
        verify = "rclone lsd shared:";
      }];
    };

    positive = {
      # One group of plain verify-command credentials, one using an
      # encoded value template.
      tokens.credentials = [ newPlainCredential ];
      encoded.credentials = [ encodedCredential ];
    };
    withGroup = name: credentials:
      positive // { ${name} = positive.${name} // { inherit credentials; }; };

    # Each fixture must produce exactly the one diagnostic it names, so no
    # fixture can pass by tripping a neighbouring rule.
    sabotages = [
      {
        name = "registry-shape";
        registry = [ positive.tokens ];
        diagnostic = "registry must be an attribute set";
      }
      {
        name = "group-schema";
        registry = positive // { malformed = { credentials = {}; }; };
        diagnostic = "group credentials must be a list";
      }
      {
        name = "empty-group";
        registry = withGroup "tokens" [];
        diagnostic = "group must declare at least one credential";
      }
      {
        name = "credential-shape";
        registry = withGroup "tokens" [ "not-a-credential" ];
        diagnostic = "credential must be an attribute set";
      }
      {
        name = "target-list";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // { targets = {}; })
        ];
        diagnostic = "credential targets must be a list";
      }
      {
        name = "empty-targets";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // { targets = []; })
        ];
        diagnostic = "credential must declare at least one target";
      }
      {
        name = "format-field";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // {
            credential = "legacy-shaped-token";
            format = "raw";
          })
        ];
        diagnostic = "credential 'legacy-shaped-token' carries 'format', which the registry no longer accepts; declare a value template instead";
      }
      {
        # A malformed registry entry can carry format with a
        # non-string (or missing) name; the refusal must still
        # produce its one diagnostic, with a placeholder name,
        # rather than aborting evaluation.
        name = "format-field-non-string-name";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // {
            credential = {};
            format = "raw";
          })
        ];
        diagnostic = "credential '?' carries 'format', which the registry no longer accepts; declare a value template instead";
      }
      {
        name = "non-string-verify";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // {
            targets = [{ system = "fixture-host"; verify = { type = "fixture-verify"; }; }];
          })
        ];
        diagnostic = "target verify must be a string command";
      }
      {
        name = "missing-verify";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // { targets = [{ system = "fixture-host"; }]; })
        ];
        diagnostic = "new targets require a non-empty one-line verify command";
      }
      {
        name = "blank-verify";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // {
            targets = [{ system = "fixture-host"; verify = "   "; }];
          })
        ];
        diagnostic = "new targets require a non-empty one-line verify command";
      }
      {
        name = "multi-line-verify";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // {
            targets = [{ system = "fixture-host"; verify = "echo one\necho two"; }];
          })
        ];
        diagnostic = "new targets require a non-empty one-line verify command";
      }
      {
        name = "value-shape";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // { value = "https://user:{secret}@host"; })
        ];
        diagnostic = "value must be an attribute set";
      }
      {
        name = "missing-template";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // { value = {}; })
        ];
        diagnostic = "value is missing template";
      }
      {
        name = "value-fields";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // {
            value = { template = "{secret}"; unexpected = true; };
          })
        ];
        diagnostic = "value has fields outside template and optional encode";
      }
      {
        name = "missing-placeholder";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // { value = { template = "missing placeholder"; }; })
        ];
        diagnostic = "value.template must contain exactly one {secret}";
      }
      {
        name = "repeated-placeholder";
        registry = withGroup "tokens" [
          newPlainCredential
          (newPlainCredential // { value = { template = "{secret}:{secret}"; }; })
        ];
        diagnostic = "value.template must contain exactly one {secret}";
      }
      {
        name = "unexported-encoder";
        registry = withGroup "encoded" [
          (encodedCredential // {
            value = encodedCredential.value // { encode = "not-exported"; };
          })
        ];
        diagnostic = "value.encode is not an exported encoding";
      }
      {
        name = "incompatible-encoding";
        registry = withGroup "tokens" [ newPlainCredential encodedCredential ];
        diagnostic = "credentials in a group must use one compatible encoding";
      }
    ];

    diagnosticsText = registry:
      "[${lib.concatStringsSep "; " (credentialRegistryDiagnostics registry)}]";
    tripsOnlyItsOwnRule = sabotage:
      credentialRegistryDiagnostics sabotage.registry == [ sabotage.diagnostic ] &&
      !(builtins.tryEval
        (builtins.deepSeq (validateCredentialRegistry sabotage.registry) true)).success;
    vacuousSabotages = builtins.filter (sabotage: !(tripsOnlyItsOwnRule sabotage)) sabotages;
    vacuousText = lib.concatMapStringsSep "; "
      (sabotage: "${sabotage.name} wanted [${sabotage.diagnostic}] got ${diagnosticsText sabotage.registry}")
      vacuousSabotages;
  in
  assert lib.assertMsg (credentialRegistryDiagnostics current == [])
    "credential-registry: public registry failed validation: ${diagnosticsText current}";
  assert lib.assertMsg (credentialRegistryDiagnostics positive == [])
    "credential-registry: positive value-template fixtures failed validation: ${diagnosticsText positive}";
  assert lib.assertMsg (vacuousSabotages == [])
    "credential-registry: sabotage fixtures accepted or tripping the wrong rule: ${vacuousText}";
  pkgs.runCommand "credential-registry-check" {} ''
    echo "credential registry validation and ${toString (builtins.length sabotages)} sabotage fixtures passed"
    touch $out
  ''
