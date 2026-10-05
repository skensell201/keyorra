# Contributing

Thanks for your interest in Keyorra.

- **Bugs and ideas**: open an [issue](https://github.com/skensell201/keyorra/issues) using a
  template. Security problems go through [SECURITY.md](SECURITY.md), never a public issue.
- **Pull requests**: please open an issue first for anything larger than a small fix, so we can
  agree on the approach. Keep changes focused and add tests for new behavior.
- **Before you push**, run the same checks as CI:

  ```bash
  cargo fmt --all --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  (cd app && pnpm install && pnpm typecheck && pnpm test)
  (cd extension && pnpm install && pnpm typecheck && pnpm test)
  ```

- Cryptography uses audited crates only; please don't add hand-written primitives.
- Code, comments, commits and docs are in English.

By contributing you agree that your work is licensed under the
[GPL-3.0-or-later](LICENSE), the license of this project.
