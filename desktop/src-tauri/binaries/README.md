# Bundled engine sidecars

Engine CI copies the version-matched PyInstaller binary here before its
unsigned package smoke. Production Desktop distribution is owned by the
`lyrashield-ai` release workflow. Tauri bundles everything in this directory
as app resources. Release builds launch only this bundled sidecar — never a
global `lyrashield` from `PATH`.
