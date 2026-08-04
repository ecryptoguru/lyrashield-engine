.PHONY: help install dev-install format format-check lint lint-check type-check security check-all clean pre-commit setup-dev dev viewer

help:
	@echo "Available commands:"
	@echo "  setup-dev     - Install all development dependencies and setup pre-commit"
	@echo "  install       - Install production dependencies"
	@echo "  dev-install   - Install development dependencies"
	@echo ""
	@echo "Code Quality:"
	@echo "  format        - Format code with ruff"
	@echo "  format-check  - Check code formatting with ruff"
	@echo "  lint          - Lint code with ruff"
	@echo "  lint-check    - Check code with ruff (no auto-fix)"
	@echo "  type-check    - Run type checking with mypy and pyright"
	@echo "  security      - Run security checks with bandit"
	@echo "  check-all     - Run all code quality checks"
	@echo ""
	@echo "Development:"
	@echo "  pre-commit    - Run pre-commit hooks on all files"
	@echo "  viewer        - Rebuild the local-viewer SPA (commit the output)"
	@echo "  clean         - Clean up cache files and artifacts"

install:
	uv sync --no-dev

dev-install:
	uv sync

setup-dev: dev-install
	uv run pre-commit install
	@echo "✅ Development environment setup complete!"
	@echo "Run 'make check-all' to verify everything works correctly."

format:
	@echo "🎨 Formatting code with ruff..."
	uv run ruff format .
	@echo "✅ Code formatting complete!"

format-check:
	@echo "🔍 Checking code formatting with ruff..."
	uv run ruff format --check .
	@echo "✅ Code formatting check complete!"

lint:
	@echo "🔍 Linting code with ruff..."
	uv run ruff check . --fix
	@echo "✅ Linting complete!"

lint-check:
	@echo "🔍 Checking code with ruff (no auto-fix)..."
	uv run ruff check .
	@echo "✅ Lint check complete!"

type-check:
	@echo "🔍 Type checking with mypy..."
	uv run mypy strix lyrashield_adapter
	@echo "✅ Type checking complete!"

security:
	@echo "🔒 Running security checks with bandit..."
	uv run bandit -r strix lyrashield_adapter -q -c pyproject.toml
	@echo "✅ Security checks complete!"

check-all: format-check lint-check type-check security
	@echo "✅ All code quality checks passed!"

pre-commit:
	@echo "🔧 Running pre-commit hooks..."
	uv run pre-commit run --all-files
	@echo "✅ Pre-commit hooks complete!"

clean:
	@echo "🧹 Cleaning up cache files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "✅ Cleanup complete!"

viewer:
	@echo "🖥️  Building the local-viewer SPA..."
	cd strix/interface/viewer/frontend && npm ci && npm run build
	@echo "✅ Viewer built to strix/interface/viewer/static/ (commit the changes)."

dev: format lint type-check

	@echo "✅ Development cycle complete!"
