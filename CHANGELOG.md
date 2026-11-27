# Changelog

## Unreleased

**Security**
- A fixed command is run only when the file it resolves to, and every directory above it, belong to root and are
  writable by root only: a link of `/usr/local/bin` into a user's home, or a binary a user may replace, is no longer
  run. A runtime installed that way is still reported when a version manager holds it (read from files).

## 0.4.0 (2026-11-27)

**Inventory**
- Runtimes installed by a version manager are now reported: Node, PHP, Python, Go, Ruby, Java and Rust installed by
  nvm, fnm, volta, n, asdf, mise, phpenv, phpbrew, pyenv, uv, goenv, gvm, go-dl, rbenv, rvm, chruby, sdkman or rustup
  in a home of `/etc/passwd`, and the Go, JDK and Rust installations of `/usr/local/go`, `/usr/lib/go-*`,
  `/usr/lib/jvm`, `/opt/*jdk*` and `/usr/local/rustup`. They are **read from files of the installation, never run**.
  A JDK also reports its implementor (and an Oracle JDK its build type). Console 1.1.0 follows their end of life.
- New fixed commands `python3* --version`, `ruby -v` and `rustc --version`. Commands are only taken from the fixed
  system directories (`/usr/local/bin`, `/usr/bin`, `/bin`, `/usr/local/sbin`, `/usr/sbin`, `/sbin`), never through
  `PATH`, and run with a reduced `PATH`.
- What a version file of a home may report is bounded by an allow-list: a version of at most 40 characters, an
  implementor or build type of at most 64.

**Container mode**
- The agent waits for the Docker API (a non-empty engine id, retried with a backoff up to 30 s) before enrolling. An
  agent whose Docker proxy never answers now keeps waiting instead of enrolling without its Docker identity.

**To know before upgrading**
- Optional, and minimal: to see the runtimes of `/root` (`0700`) or of Ubuntu's `/home/*` (`0750`), give the agent
  user `--x` on the home and `rX` on the version manager's directory only (see the README). Never `-R rX` on `/root`
  or `/home`.
- The paths of these runtimes, hence the names of the accounts holding them, are sent to the console.
- The first inventory after the upgrade scans every Docker image again (the cache is keyed by the agent version).
- The end-of-life findings of the runtimes seen for the first time open at once: expect a wave of notifications.
- The systemd unit is unchanged. `host` mode: upgrade from the console (**Upgrade to 0.4.0**). `container` and
  `embedded` modes: change the image digest to the one of `ghcr.io/dependencyverifier/agent:0.4.0`.

## 0.3.0 (2026-11-14)

- `embedded` mode (inside an application's image), SUSE `ndb` package databases and the Red Hat channel of RHEL.

## 0.2.0 (2026-11-13)

- PHP-FPM pools, RPM databases of images, container runtimes and required versions; remote upgrade (`UPGRADE_AGENT`)
  and key rotations (`ROTATE_KEY`, `ROTATE_CONSOLE_KEY`); file reads confined to the root, bounded RPM readers.

## 0.1.0 (2026-11-13)

- First release: protocol v1 (enrollment, signed polling, `SCAN_NOW` / `SET_CONFIG`, inventories), `host` and
  `container` modes, signed releases.
