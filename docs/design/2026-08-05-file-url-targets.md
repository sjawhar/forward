# file:// URL targets for `forward open`

2026-08-05

## Problem

`forward open /path/to/doc.md` works: the path becomes a preview URL
(`http://<listen>:12802/...`) and the laptop browser opens it. But
`forward open file:///path/to/doc.md` fails: the URL parses as a valid
hierarchical URL in `target::to_url`, passes through unchanged, and the
laptop daemon's scheme whitelist (`http`/`https` only, `request.rs`)
drops it.

Agents and TUIs emit `file://` links routinely. Terminal URL pickers
(e.g. tmux-urls) hand them to `forward open` verbatim, so the scheme
must be accepted on the devbox.

## Design

Convert `file://` URLs to preview URLs on the devbox, in
`target::to_url`. After `Url::parse` succeeds, a `file` scheme branch
converts the URL via `Url::to_file_path()` and feeds the result through
the existing bare-path flow: canonicalize → percent-encode →
`http://<listen>:<files_port>/<path>`.

`forward open file:///home/u/doc.md` is exactly equivalent to
`forward open /home/u/doc.md`.

Details:

- `to_file_path()` percent-decodes (`a%20b.md` round-trips through the
  existing `encode_path`) and fails for a non-local host
  (`file://otherhost/path`) → `TargetError::Invalid`.
- The URL fragment is preserved on the preview URL
  (`file:///doc.md#anchor` → `http://…/doc.md#anchor`); anchors are
  common in agent-emitted links.
- Missing file → existing `TargetError::NotFound`, same as a bare path.
- No laptop-side or protocol change. The laptop only ever sees the http
  preview URL, so the security model (peer address check, scheme
  whitelist) is untouched.

## Alternatives rejected

- **Whitelist `file` on the laptop daemon and let the opener handle
  it**: the file lives on the devbox, not the laptop; `xdg-open
  file://…` on the laptop would open the wrong (or no) file.
- **Strip the `file://` prefix as a string before parsing**: misses the
  percent-decoding and host validation `to_file_path()` provides.

## Companion change (outside this repo)

`~/.dotfiles/scripts/tmux-urls` greps `(https?|ftp)://`; extend the
pattern to include `file://` so the picker lists such links and routes
them through `forward open`.

## Testing

Unit tests in `src/target/tests.rs`:

- `file:///…` of an existing file → preview URL with correct host,
  port, path.
- Percent-encoded file URL round-trips (`a%20b.md`).
- `file://otherhost/path` → `Invalid`.
- Missing file → `NotFound`.
- Fragment preserved.

Manual end-to-end: `forward open file:///…` on a real file opens the
preview in the laptop browser.
