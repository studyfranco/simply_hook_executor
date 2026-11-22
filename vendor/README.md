# Dependency patches

- SeaORM 2.0.4 from crates.io. The package manifest drops two weak feature
  edges. The application enables both JSON and time support directly. Cargo
  otherwise records the optional date library through the JSON edge and Arrow
  through the time edge, even with SeaORM defaults disabled. Neither optional
  package is required by the application. The Rust source is upstream.
- russh-util 0.52.0 from crates.io. On WebAssembly, the clock now uses
  `web_time::Instant` for elapsed time. Native targets use the upstream
  `std::time::Instant` re-export. Cargo resolves the WebAssembly dependencies
  into the same lockfile as the native dependencies.

Drop the patches when released upstream versions resolve without the old
date library. Check the complete resolution with `cargo tree --target all`
and `cargo audit --deny warnings`.
