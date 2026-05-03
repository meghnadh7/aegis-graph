.PHONY: setup setup-kb generate-alerts demo eval eval-summary test docker-up docker-down clean

# `make demo` is what gets shown in the Loom recording. We force MOCK_MODE so
# nothing tries to call out to the network, and we shut off LangSmith tracing
# (a placeholder LANGCHAIN_API_KEY in .env causes a noisy 403 on shutdown).
demo:
	PYTHONPATH=. MOCK_MODE=true LANGCHAIN_TRACING_V2=false python scripts/run_demo.py

setup:
	pip install -r requirements.txt
	@test -f .env || cp .env.example .env
	python scripts/check_deps.py

setup-kb:
	PYTHONPATH=. python scripts/setup_knowledge_base.py

generate-alerts:
	PYTHONPATH=. python scripts/generate_alerts.py

eval:
	PYTHONPATH=. LANGCHAIN_TRACING_V2=false python -m evals.run_evals --concurrency 16

eval-summary:
	PYTHONPATH=. python scripts/eval_summary.py

test:
	PYTHONPATH=. LANGCHAIN_TRACING_V2=false pytest tests/ -v

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
