.PHONY: setup setup-kb generate-alerts demo eval test docker-up docker-down clean

setup:
	pip install -r requirements.txt
	@test -f .env || cp .env.example .env
	python scripts/check_deps.py

setup-kb:
	python scripts/setup_knowledge_base.py

generate-alerts:
	python scripts/generate_alerts.py

demo:
	python scripts/run_demo.py

eval:
	python -m evals.run_evals

test:
	pytest tests/ -v

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
