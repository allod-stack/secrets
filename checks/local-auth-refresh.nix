{ lib, pkgs, localAuthRefreshDiagnostics, mkLocalAuthRefreshSources, credentialStoreUrlSourceClause, rotationRegistry }:
  let
    refreshCredential = {
      credential = "fixture-forge-token";
      secret_path = "secrets/fixture-forge-token.age";
      value = { template = "https://template-user:{secret}@template.example"; };
      targets = [{
        system = "fixture-host";
        deployed_path = "/root/.git-credentials";
        verify = "git ls-remote https://template.example/fixture.git HEAD";
      }];
    };
    refreshEntry = {
      contract = "nixos-netrc-from-root-git-credentials";
      source_credential = "fixture-forge-token";
      system = "fixture-host";
      local_username = "fixture-user";
    };
    positive = {
      fixture = {
        credentials = [ refreshCredential ];
        local_auth_refresh = [ refreshEntry ];
      };
    };
    withGroupField = field: value:
      positive // { fixture = positive.fixture // { ${field} = value; }; };
    withEntry = entry: withGroupField "local_auth_refresh" [ entry ];
    withCredential = credential: withGroupField "credentials" [ credential ];

    # Each fixture must produce exactly the one diagnostic it names, so
    # no fixture can pass by tripping a neighbouring rule.
    sabotages = [
      {
        name = "refresh-list-shape";
        registry = withGroupField "local_auth_refresh" {};
        diagnostic = "fixture: local_auth_refresh is not an array";
      }
      {
        # A boolean is not a list, so it is refused; an explicit null is
        # not sabotage at all and is asserted below instead.
        name = "refresh-list-boolean";
        registry = withGroupField "local_auth_refresh" false;
        diagnostic = "fixture: local_auth_refresh is not an array";
      }
      {
        name = "entry-shape";
        registry = withEntry "not-an-entry";
        diagnostic = "fixture: a local_auth_refresh entry is not an attribute set";
      }
      {
        name = "unsupported-contract";
        registry = withEntry (refreshEntry // { contract = "run-arbitrary-command"; });
        diagnostic = "fixture: a local_auth_refresh entry has unsupported contract 'run-arbitrary-command'";
      }
      {
        name = "missing-system";
        registry = withEntry (builtins.removeAttrs refreshEntry [ "system" ]);
        diagnostic = "fixture: a local_auth_refresh entry has no system";
      }
      {
        name = "missing-local-username";
        registry = withEntry (builtins.removeAttrs refreshEntry [ "local_username" ]);
        diagnostic = "fixture: a local_auth_refresh entry has no local_username";
      }
      {
        name = "missing-source-credential";
        registry = withEntry (builtins.removeAttrs refreshEntry [ "source_credential" ]);
        diagnostic = "fixture: a local_auth_refresh entry has no source_credential";
      }
      {
        name = "local-username-shape";
        registry = withEntry (refreshEntry // { local_username = "1-not-a-user"; });
        diagnostic = "fixture: local_username '1-not-a-user' is not a valid user name";
      }
      {
        name = "unknown-source-credential";
        registry = withEntry (refreshEntry // { source_credential = "missing-credential"; });
        diagnostic = "fixture: source_credential 'missing-credential' names 0 credentials of this group, not exactly one";
      }
      {
        name = "missing-secret-path";
        registry = withCredential (builtins.removeAttrs refreshCredential [ "secret_path" ]);
        diagnostic = "fixture: source credential 'fixture-forge-token' has no secret_path";
      }
      {
        # The clause is pinned by its text, not by "some diagnostic":
        # every other sabotage here would reject this fixture too.
        name = "template-is-not-a-credential-store-url";
        registry = withCredential (refreshCredential // {
          value = { template = "http://template-user:{secret}@template.example"; };
        });
        diagnostic = "fixture: source credential 'fixture-forge-token' ${credentialStoreUrlSourceClause}";
      }
      {
        name = "wrong-deployed-path";
        registry = withCredential (refreshCredential // {
          targets = map (target: target // { deployed_path = "/tmp/wrong-git-credentials"; })
            refreshCredential.targets;
        });
        diagnostic = "fixture: source credential 'fixture-forge-token' has no single target at fixture-host:/root/.git-credentials";
      }
    ];

    diagnosticsText = registry:
      "[${lib.concatStringsSep "; " (localAuthRefreshDiagnostics registry)}]";
    tripsOnlyItsOwnRule = sabotage:
      localAuthRefreshDiagnostics sabotage.registry == [ sabotage.diagnostic ] &&
      !(builtins.tryEval
        (builtins.deepSeq (mkLocalAuthRefreshSources sabotage.registry) true)).success;
    vacuousSabotages = builtins.filter (sabotage: !(tripsOnlyItsOwnRule sabotage)) sabotages;
    vacuousText = lib.concatMapStringsSep "; "
      (sabotage: "${sabotage.name} wanted [${sabotage.diagnostic}] got ${diagnosticsText sabotage.registry}")
      vacuousSabotages;

    # A group that declares `local_auth_refresh: null` refreshes nothing
    # and is not an error: the jq this replaces read it through `//`, and
    # the registry validator accepts it, so refusing it here would make
    # the export throw on a registry that works today.
    nullRefreshRegistry = withGroupField "local_auth_refresh" null;

    projection = mkLocalAuthRefreshSources rotationRegistry;
    missingGroups = builtins.filter
      (groupAlias: !(builtins.hasAttr groupAlias projection))
      (builtins.attrNames rotationRegistry);
  in
  assert lib.assertMsg (localAuthRefreshDiagnostics rotationRegistry == [])
    "local-auth-refresh: public registry failed validation: ${diagnosticsText rotationRegistry}";
  assert lib.assertMsg (localAuthRefreshDiagnostics positive == [])
    "local-auth-refresh: positive fixture failed validation: ${diagnosticsText positive}";
  assert lib.assertMsg (localAuthRefreshDiagnostics nullRefreshRegistry == [])
    "local-auth-refresh: an explicit null local_auth_refresh was refused: ${diagnosticsText nullRefreshRegistry}";
  assert lib.assertMsg ((mkLocalAuthRefreshSources nullRefreshRegistry).fixture == [])
    "local-auth-refresh: an explicit null local_auth_refresh did not project to an empty list";
  assert lib.assertMsg (missingGroups == [])
    "local-auth-refresh: projection does not key every group alias: ${lib.concatStringsSep ", " missingGroups}";
  assert lib.assertMsg ((builtins.tryEval (builtins.deepSeq projection true)).success)
    "local-auth-refresh: the projection of the public registry does not evaluate";
  assert lib.assertMsg (vacuousSabotages == [])
    "local-auth-refresh: sabotage fixtures accepted or tripping the wrong rule: ${vacuousText}";
  pkgs.runCommand "local-auth-refresh-check" {} ''
    echo "local-auth-refresh projection and ${toString (builtins.length sabotages)} sabotage fixtures passed"
    touch $out
  ''
