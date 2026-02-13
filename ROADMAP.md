# SteamFlow roadmap

## References from legacy OpenSteamClient
- `OpenSteamworks.Client/Login/LoginManager.cs`: credential + steam-guard + token exchange behavior.
- `OpenSteamworks.Client/Login/LoginPoll.cs`: polling semantics for auth session state and token generation.
- `OpenSteamworks.Client/Apps/Library/LibraryManager.cs`: Steam library parsing references.
- `tools/binaryvdfparser_src/Program.cs`: binary VDF support ideas for `appinfo.vdf`.

## Current auth baseline
- ✅ SteamFlow uses steam-vent 0.4.2 full auth pipeline (`Connection::login` / `Connection::access`), including:
  - RSA credential exchange and auth-session creation.
  - Steam Guard challenge handling.
  - PollAuthSessionStatus token retrieval.
  - Refresh-token-based client logon and persisted session restore.

## Next milestones
1. ✅ SteamFlow uses steam-vent 0.4.2 full auth pipeline, including persisted sessions.
2. ✅ Improved Steam Guard UX with confirmation-type specific hints.
3. ✅ Integrated 4-phase download pipeline logic (`manifest id -> security -> manifest -> chunks`).
4. [x] Improve download UI with real-time progress reporting and better error handling.
5. [x] Integrate PICS metadata fetch into the main `SteamClient` launch flow.
6. [ ] Add per-game launch profiles (env vars, custom args, compat tool preset).
7. [x] Add settings view for Proton runtime and Steam library path discovery.
8. [ ] Extend CI to publish signed .deb artifacts from tags.
9. [x] Implement Steam Cloud Sync (Enumerate/Download/Upload).

10. [x] Add Depot Browser developer tooling (depot list, manifest tree, single-file download).
11. [x] Harden library scanning fallback and appmanifest parse diagnostics.
