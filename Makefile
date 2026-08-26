.PHONY: dev up down logs test seed demo-full demo-generate

up:
	docker-compose up -d --build

logs:
	docker-compose logs -f --tail=200

down:
	docker-compose down

dev: up
	@echo "UI:  http://127.0.0.1:6080"
	@echo "API: http://127.0.0.1:5051/health"
	@echo "KC:  http://127.0.0.1:8080 (realm: tesht, user: demo-user/demo)"

# Backend tests (assumes backend/.venv exists)

test:
	cd backend && . .venv/bin/activate && pytest

# Generate synthetic data (500+ agents, 150+ adversarial scenarios)
demo-generate:
	cd sdk/python && python ../../tests/synthetic/generate.py

# Full end-to-end demo:
#   1. Start backend in SQLite dev mode
#   2. Run 8 SDK demo scenarios
#   3. Check backend API health
#   4. Run scenario subset from synthetic data
#   5. Print summary matrix
#   6. Exit 0 if all pass
demo-full:
	@./scripts/demo_full.sh
