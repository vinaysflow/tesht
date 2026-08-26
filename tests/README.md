## Test harness (project root)

This folder provides repeatable commands for running the Tesht test suites.

### Local (venv) backend tests

```bash
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-test.txt
pytest
```

### Docker (compose) backend tests

```bash
# from the repo root
docker-compose up -d
docker-compose exec backend pytest -q
```

### Reports
- HTML coverage (local): `backend/htmlcov/`
- HTML pytest report (local): `tests/reports/`
