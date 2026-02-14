# SteamFlow TODO & Roadmap

## Immediate Priorities (Alpha)
- [x] **Search & Filtering**
  - [x] Implement a search bar in the library sidebar.
  - [x] Filter by installed/uninstalled.
  - [ ] Filter by genre/tags.
- [ ] **Download Manager Improvements**
  - [ ] Better visualization of download progress (speed, time remaining).
  - [ ] Queue management (pause, resume, reorder).
  - [ ] Proper handling of multiple depots.
- [ ] **Game Launching Polish**
  - [x] Better Proton detection and selection.
  - [ ] Support for custom launch options/arguments.
  - [ ] Environment variable support for games.
- [x] **UI/UX Polish**
  - [x] Context menus for games (Install, Uninstall, Properties).
  - [ ] Better error reporting in the UI.
  - [ ] Responsive layout improvements.

## Medium Term (Beta)
- [ ] **Friends & Social**
  - Simple friends list.
  - Online/Offline status.
  - Chat support.
- [ ] **Workshop Support**
  - View subscribed items.
  - Simple enable/disable mod management.
- [ ] **Collections**
  - Support for Steam's native collections.
  - Custom local collections.

## Long Term / Future
- [x] **Depot Browser**
  - [x] Advanced tool for downloading specific game versions or individual files.
- [ ] **Achievements UI**
  - Display achievements and progress.
- [ ] **Store/Community Proxy**
  - Display store pages without using a full browser engine (maybe via simplified HTML/Markdown rendering or proxied data).
- [ ] **Settings UI**
  - Comprehensive client settings.
  - Account management.

## Technical Debt & Refactoring
- [ ] **Better Error Handling**
  - Move away from `anyhow` in some core components to more specific error types.
- [ ] **Testing**
  - Add unit tests for `steam_client` logic.
  - Add tests for download pipeline state machine.
- [ ] **Modularization**
  - Split `ui.rs` into smaller components (Sidebar, GameView, Auth, etc.).

## Done
- [x] **Steam Cloud**
  - Sync game saves on launch/exit.
  - [ ] Conflict resolution UI.
