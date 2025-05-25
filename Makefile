# Development Makefile for ELF Watermarking Framework

.PHONY: help install dev-install format lint type-check test test-cov clean all ci

help: ## Show this help message
	@echo "🔧 ELF Watermarking Framework - Development Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install the project dependencies
	poetry install

dev-install: ## Install development dependencies
	poetry install --with dev

format: ## Format code with Ruff
	poetry run ruff format .
	poetry run ruff check --fix .

lint: ## Lint code with Ruff (no auto-fix)
	poetry run ruff check .

type-check: ## Run type checking with mypy
	poetry run mypy watermark_framework/

test: ## Run tests
	poetry run pytest

test-cov: ## Run tests with coverage report
	poetry run pytest --cov=watermark_framework --cov-report=html --cov-report=term

clean: ## Clean up generated files
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

all: format lint type-check test ## Run all checks (format, lint, type-check, test)

ci: lint type-check test ## Run CI checks (lint, type-check, test) - no formatting