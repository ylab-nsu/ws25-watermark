.PHONY: lint format check

check: lint format-check type-check

lint:
	poetry run ruff check .

format-check:
	poetry run isort --check --diff .
	poetry run ruff format --check .

format:
	poetry run isort .
	poetry run ruff format .

type-check:
	poetry run mypy .

fix:
	poetry run ruff check --fix .
	poetry run isort .
	poetry run ruff format .