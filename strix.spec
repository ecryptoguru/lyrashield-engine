# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

project_root = Path(SPECPATH)
strix_root = project_root / 'strix'
lyrashield_root = project_root / 'lyrashield'

datas = []

for package_root in (strix_root, lyrashield_root):
    for pattern in ('skills/**/*.md', '**/*.jinja', '**/*.xml', '**/*.tcss'):
        for data_file in package_root.rglob(pattern):
            rel_path = data_file.relative_to(project_root)
            datas.append((str(data_file), str(rel_path.parent)))

    # Prebuilt local-viewer SPA (served by `lyrashield view`).
    viewer_static = package_root / 'interface' / 'viewer' / 'static'
    for asset in viewer_static.rglob('*'):
        if asset.is_file():
            rel_path = asset.relative_to(project_root)
            datas.append((str(asset), str(rel_path.parent)))

datas += collect_data_files('textual')

datas += collect_data_files('tiktoken')
datas += collect_data_files('tiktoken_ext')

datas += collect_data_files('litellm')

datas += collect_data_files('agents', includes=['**/*.md', '**/*.jinja', '**/*.json'])

hiddenimports = [
    # Core dependencies
    'litellm',
    'litellm.llms',
    'litellm.llms.openai',
    'litellm.llms.anthropic',
    'litellm.llms.vertex_ai',
    'litellm.llms.bedrock',
    'litellm.utils',
    'litellm.caching',

    # Textual TUI
    'textual',
    'textual.app',
    'textual.widgets',
    'textual.containers',
    'textual.screen',
    'textual.binding',
    'textual.reactive',
    'textual.css',
    'textual._text_area_theme',

    # Rich console
    'rich',
    'rich.console',
    'rich.panel',
    'rich.text',
    'rich.markup',
    'rich.style',
    'rich.align',
    'rich.live',

    # Pydantic
    'pydantic',
    'pydantic.fields',
    'pydantic_core',
    'email_validator',

    # Docker
    'docker',
    'docker.api',
    'docker.models',
    'docker.errors',

    # HTTP/Networking
    'httpx',
    'httpcore',
    'requests',
    'urllib3',
    'certifi',

    # Jinja2 templating
    'jinja2',
    'jinja2.ext',
    'markupsafe',

    # Syntax highlighting
    'pygments',
    'pygments.lexers',
    'pygments.styles',
    'pygments.util',

    # Tiktoken (for token counting)
    'tiktoken',
    'tiktoken_ext',
    'tiktoken_ext.openai_public',

    # Tenacity retry
    'tenacity',

    # CVSS scoring
    'cvss',

    # Strix modules
    'strix',
    'strix.interface',
    'strix.interface.main',
    'strix.interface.cli',
    'strix.interface.tui',
    'strix.interface.tui.history',
    'strix.interface.tui.live_view',
    'strix.interface.utils',
    'strix.agents',
    'strix.agents.factory',
    'strix.agents.prompt',
    'strix.config.models',
    'strix.core',
    'strix.core.agents',
    'strix.core.execution',
    'strix.core.inputs',
    'strix.core.paths',
    'strix.core.runner',
    'strix.core.sessions',
    'strix.report',
    'strix.report.dedupe',
    'strix.report.state',
    'strix.report.writer',
    'strix.interface.viewer',
    'strix.interface.viewer.auth',
    'strix.interface.viewer.cli',
    'strix.interface.viewer.report_pdf',
    'strix.interface.viewer.server',
    'strix.interface.viewer.transcript',

    # PDF report generation + encryption
    'reportlab',
    'reportlab.pdfgen',
    'reportlab.pdfbase',
    'reportlab.lib',
    'reportlab.platypus',
    'pypdf',
    'cryptography',
    'strix.runtime',
    'strix.runtime.backends',
    'strix.runtime.caido_bootstrap',
    'strix.runtime.docker_client',
    'strix.runtime.session_manager',
    'strix.telemetry',
    'strix.telemetry.logging',
    'strix.telemetry.posthog',
    'strix.tools',
    'strix.tools.agents_graph.tools',
    'strix.tools.finish.tool',
    'strix.tools.notes.tools',
    'strix.tools.proxy.tools',
    'strix.tools.reporting.tool',
    'strix.tools.thinking.tool',
    'strix.tools.todo.tools',
    'strix.skills',

    # LyraShield product modules with runtime-loaded resources.
    'lyrashield.agents.factory',
    'lyrashield.agents.prompt',
    'lyrashield.interface.tui.app',
    'lyrashield.interface.tui.renderers',
    'lyrashield.interface.viewer.server',
    'lyrashield.skills',
]

hiddenimports += collect_submodules('textual')
hiddenimports += collect_submodules('rich')
hiddenimports += collect_submodules('pydantic')
hiddenimports += collect_submodules('pygments')
# reportlab loads renderers/fonts dynamically, so pull its whole tree in.
hiddenimports += collect_submodules('reportlab')

# reportlab ships bundled fonts (.pfb/.afm) it needs at runtime.
datas += collect_data_files('reportlab')

# reportlab imports PIL (pillow) lazily for image handling, so it must be
# bundled explicitly and kept out of the excludes list below.
hiddenimports += collect_submodules('PIL')
datas += collect_data_files('PIL')

excludes = [
    # Sandbox-only packages
    'playwright',
    'playwright.sync_api',
    'playwright.async_api',
    'IPython',
    'ipython',
    'libtmux',
    'pyte',
    'openhands_aci',
    'openhands-aci',
    'numpydoc',

    # Google Cloud / Vertex AI
    'google.cloud',
    'google.cloud.aiplatform',
    'google.api_core',
    'google.auth',
    'google.oauth2',
    'google.protobuf',
    'grpc',
    'grpcio',
    'grpcio_status',

    # Test frameworks
    'pytest',
    'pytest_asyncio',
    'pytest_cov',
    'pytest_mock',

    # Development tools
    'mypy',
    'ruff',
    'black',
    'isort',
    'pylint',
    'pyright',
    'bandit',
    'pre_commit',

    # Unnecessary for runtime
    'tkinter',
    'matplotlib',
    'numpy',
    'pandas',
    'scipy',
    'cv2',
]

a = Analysis(
    ['lyrashield_adapter/cli.py'],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='strix',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
