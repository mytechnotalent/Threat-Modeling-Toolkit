.PHONY: install test scan scan-llm clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --cov=tmt --cov-report=term-missing

scan:
	python run_threat_model.py --target . --project-name "tmt-self-scan"

scan-llm:
	python run_threat_model.py --target . --project-name "tmt-self-scan" --llm

clean:
	rm -rf reports/ .pytest_cache __pycache__ tmt/__pycache__ tmt/**/__pycache__ tests/__pycache__
	find . -name "*.pyc" -delete
