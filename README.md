# TypeScript Playwright — OWASP Juice Shop Security Regression Suite

Automated security regression tests targeting [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) running in Docker. Tests verify that known vulnerability classes (SQLi, XSS) are **not exploitable**. A failing test means a live vulnerability was detected — that is the framework working as intended.

## Project Structure

```
src/
  components/       # Component Object Model (COM) — global UI fragments
  pages/            # Page Object Model (POM) — full page classes
  tests/            # Test specs (security/)
.github/workflows/  # CI pipeline — runs on push/PR to main, deploys reports to GitHub Pages
```

## Prerequisites

- [Node.js 20+](https://nodejs.org/)
- [Docker](https://www.docker.com/)

## Setup

```bash
npm ci
npx playwright install --with-deps chromium
```

## Running Tests

### 1. Start Juice Shop

```bash
docker compose up -d
```

The container performs an internal health-check and is ready once `docker compose ps` shows `healthy`. To stop it:

```bash
docker compose down
```

### 2. Run the full test suite

```bash
npm test
```

### 3. Run a single spec

```bash
npx playwright test src/tests/sqli.spec.ts
npx playwright test src/tests/xss.spec.ts
```

### 4. Run with a visible browser

```bash
npx playwright test --headed
```

## Reports

### Playwright HTML report

```bash
npm run report:html
```

Opens the built-in Playwright viewer at `reports/html/index.html` with traces, screenshots, and video for every failed test. A local port is opened automatically.

### Allure report

```bash
npx allure generate reports/allure-results --clean -o reports/allure-report
npm run report:allure
```

`allure serve` generates and serves the report in one step and opens a browser tab automatically. The report includes historical trend graphs across runs.

## CI / GitHub Pages

The GitHub Actions workflow (`.github/workflows/playwright-security.yml`) runs on every push and pull request to `main`/`master`. It:

1. Spins up Juice Shop as a Docker service container
2. Installs dependencies and Playwright browsers
3. Executes the full test suite
4. Generates both the Playwright HTML and Allure reports
5. Deploys a combined report landing page to GitHub Pages

Reports are always published — even when tests fail — so vulnerability findings are immediately visible.

## Interpreting Results

| Test result | Meaning |
|---|---|
| **Pass** | The attack payload was blocked — the app is not vulnerable to this vector |
| **Fail** | The attack payload succeeded — a vulnerability is present and must be fixed |

> Juice Shop is intentionally vulnerable by design. SQLi bypass tests will fail against a default instance. This is expected and confirms the detection logic is working correctly.
