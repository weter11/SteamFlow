# Third-party notices

SteamFlow itself is MIT licensed; see [`LICENSE`](LICENSE). This file covers
the third-party code that ships inside the repository.

## `vendor/steam-vent` — steam-vent 0.6.0 (MIT)

`vendor/steam-vent/` is a verbatim `git archive` of steam-vent revision
`54ecd10ebd385c6879a536725fd77cdb846fc9a3` (recorded in
`vendor/steam-vent/STEAMVENT_REV`), plus nothing. It is vendored rather than
taken as a `rev = "<sha>"` git dependency because the revision is an
unadvertised `refs/pull/19/head` commit, which Cargo's git fetcher cannot
resolve. See `AGENTS.md` for the refresh procedure and
`tests/steam_vent_git_pin.rs` for the offline guard on the pin.

Upstream: <https://codeberg.org/steam-vent/steam-vent>

steam-vent's `Cargo.toml` declares `license = "MIT"` and
`authors = ["Robin Appelman <robin@icewind.nl>"]`, but the upstream repository
ships no `LICENSE` file, so `git archive` cannot carry one into the vendored
tree. The MIT license therefore travels with this file rather than inside the
vendored directory — adding a file there would make the tree diverge from the
pinned revision that `tests/steam_vent_git_pin.rs` asserts.

```
MIT License

Copyright (c) Robin Appelman and the steam-vent contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## `vendor/steam-cdn` — steam-cdn (Apache-2.0)

`vendor/steam-cdn` is a locally patched steam-cdn and keeps its upstream
`LICENSE` (Apache License 2.0) in place at `vendor/steam-cdn/LICENSE`.

## `machine_id.lock` is not a vendored-code concern

`~/.config/SteamFlow/machine_id.lock` is created by SteamFlow, not shipped: it
is the handle for a `flock(2)` used to serialize first-run machine-identity
initialization between concurrent SteamFlow processes. Its presence means
nothing — the kernel owns the lock and releases it when the process exits, which
is why a crashed run cannot leave the identity permanently uninitializable. It is
created `0600` like the other files in that directory.

## Three `reqwest` majors in `Cargo.lock`

The lockfile carries reqwest 0.11.27, 0.12.28 and 0.13.5 at once. They come
from three different manifests and the duplication is not removable from this
side:

| version | required by | predates the steam-vent vendoring? |
| --- | --- | --- |
| 0.11.27 | `vendor/steam-cdn/Cargo.toml` (`version = "0.11"`) | yes |
| 0.12.28 | `Cargo.toml` (`reqwest = "0.12"`) | yes |
| 0.13.5 | `vendor/steam-vent/Cargo.toml` (`version = "0.13.2"`) | no — introduced by it |

So vendoring added a third major rather than none. Collapsing them would mean
editing a third-party manifest inside `vendor/`, which the vendoring rules
forbid; it resolves when upstream steam-vent moves to a reqwest that matches,
or when steam-cdn is updated. Any dependency summary for this tree should say
so explicitly instead of claiming no duplicates were introduced.
