# PrivacyGuard for Horizen — Local Development Starter

This is the first full-stack development scaffold for PrivacyGuard:
- Next.js + TypeScript frontend
- FastAPI backend
- Slither static analysis (when compilation succeeds)
- Initial privacy-focused heuristic checks
- Docker Compose to run the app locally

## Run on a Mac with Docker Desktop

1. Extract the ZIP.
2. Open the extracted `privacyguard-app` folder in VS Code.
3. In VS Code, choose **Terminal → New Terminal**.
4. Run:

   ```bash
   docker compose up --build
   ```

   The first build can take several minutes because it downloads dependencies and a Solidity compiler.

5. Open `http://localhost:3000` in your browser.
6. API health check: `http://localhost:8000/health`

To stop it, click the terminal and press `Control + C`. To remove the stopped containers, run `docker compose down`.

## Current capabilities

- Paste Solidity source into the browser UI.
- Submit source to the local FastAPI backend.
- Backend performs a few heuristic privacy checks.
- Backend attempts Slither static analysis and includes its findings when compilation succeeds.
- Results include severity, rule ID, source line when available, explanation, and recommendation.

## Important limitations

This is an early development scaffold, not a production security product. Heuristic rules can produce false positives and false negatives. Slither may fail on contracts that need imports, specific compiler versions, remappings, or project configuration. This version accepts a single Solidity source file and does not resolve arbitrary project dependencies.

Do not submit confidential source code unless you understand the local network and runtime setup. The backend writes a temporary source file inside its container for analysis and deletes it afterward. No hosted service or database is used in this scaffold.

A clean scan is not proof of security or privacy. Use tests, manual review, and professional audits for production contracts.
