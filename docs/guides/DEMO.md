## Demo

After `make dev`:

- UI: `http://127.0.0.1:6080`
- API: `http://127.0.0.1:5051`

### Guided demo (recommended)

1. Open [http://127.0.0.1:6080/demo](http://127.0.0.1:6080/demo)
2. Click **Run Drift Demo**
3. Copy VC JWT and verify results
4. Click **Reset my demo** to clear your tenant data

Expected: `verify_before.verified=true` and `verify_after.reason=revoked`.

### Local OIDC

- Use `http://127.0.0.1:6080/login` for Keycloak login.
- Or run the single-call API demo:

```bash
API_BASE=http://127.0.0.1:5051 ./scripts/demo_oidc.sh
```
