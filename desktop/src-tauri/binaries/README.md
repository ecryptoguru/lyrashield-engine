# Bundled engine sidecars

The release workflow (`release-tauri.yml`) copies the version-matched
PyInstaller engine binary here as `lyrashield-engine[-triple][.exe]` before
`cargo tauri build`; Tauri bundles everything in this directory as app
resources. Release builds launch only this bundled sidecar — never a global
`lyrashield` from `PATH`.
