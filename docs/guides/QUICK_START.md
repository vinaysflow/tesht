## Quick start (local)

### 1) Configure env

```bash
# from the repo root after cloning
cd Tesht-protocol
cp .env.example .env
python3 scripts/set_env_secret.py
```

### 2) Run stack (Postgres + Keycloak + API + UI)

```bash
make dev
```

- UI: `http://127.0.0.1:6080`
- API health: `http://127.0.0.1:5051/health`
- API ready: `http://127.0.0.1:5051/ready`
- Keycloak: `http://127.0.0.1:8080` (realm `tesht`)

### 3) Login

Open `http://127.0.0.1:6080/login`.

Demo users seeded in Keycloak realm import:
- `demo-user / demo`
- `demo-admin / admin`
- `acme-user / acme`
