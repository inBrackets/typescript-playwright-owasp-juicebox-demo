# CLAUDE.md — Development Guidelines

## Architecture

- **OOP & SOLID**: All test infrastructure must follow Object-Oriented Programming and SOLID principles.
  - Single Responsibility: each class has one purpose.
  - Open/Closed: extend behavior through inheritance or composition, not modification.
  - Liskov Substitution: subclasses must be substitutable for their base types.
  - Interface Segregation: prefer small, focused interfaces over large ones.
  - Dependency Inversion: depend on abstractions, not concretions.
- **Page Object Model (POM)**: Every full page gets its own class (e.g., `LoginPage`, `ProductPage`). Page classes encapsulate all locators and interactions for that page. Tests never contain raw locators.
- **Component Object Model (COM)**: Global layout fragments (navigation bar, header, footer, modals) get their own component classes (e.g., `NavBarComponent`, `SearchComponent`). Pages compose components rather than duplicating logic.
- **DRY**: Shared logic (auth helpers, API clients, fixture setup) lives in reusable utility or base classes — never copy-pasted across tests.
- **KISS**: Prefer simple, readable implementations. Avoid clever abstractions that obscure intent.
- **YAGNI**: Do not implement features, helpers, or base classes that no current test requires.

## Code Style

- **Explicit TypeScript typing**: All function parameters, return types, class properties, and variables must have explicit types. Avoid `any`.
- **Access modifiers**: All class members must declare `public`, `private`, or `protected`. No implicit public.
- **Readonly**: Mark properties that should not be reassigned as `readonly`.
- **Strict mode**: `tsconfig.json` must enable `"strict": true`.

## Framework Goal

This framework performs **regression testing** against an OWASP Juice Shop instance running in Docker.

- Tests verify that known vulnerability categories (SQLi, XSS, broken auth, etc.) are **not exploitable** in the deployed instance.
- Assertions must **fail explicitly** when a vulnerability is successfully exploited. A test that silently passes when an attack succeeds is a critical defect in the framework itself.
- Each security test must include a `// FAILURE CONDITION:` comment above its assertion explaining what it means for the test to fail.
- Each vulnerability test must document the **CVE or OWASP category** it targets in a `@tag` or inline comment.
- Security regression tests belong in `src/tests/security/`. Functional smoke tests belong in `src/tests/functional/`.

## Project Structure

```
src/
  pages/            # POM page classes (BasePage, LoginPage, MainPage, etc.)
  components/       # COM component classes (NavBarComponent, etc.)
  fixtures/         # Playwright fixture extensions
  helpers/
    api-client.ts   # JuiceShopApiClient — typed REST wrapper
    auth.helper.ts  # AuthHelper — login/register utilities
  tests/
    functional/     # Functional regression tests
    security/       # Security regression tests (SQLi, XSS, etc.)
```

## Helpers

### `JuiceShopApiClient` (`src/helpers/api-client.ts`)

The sole HTTP client for all API-level tests. Wraps `APIRequestContext` with typed methods. Default base URL is `http://localhost:3000` — **do not pass the base URL explicitly**; use `new JuiceShopApiClient(request)`.

```typescript
const client = new JuiceShopApiClient(request);
await client.get('/api/Products');
await client.post('/api/Users/login', { email, password }, token);
await client.put('/api/Products/1', { description: '...' }, adminToken);
await client.postRaw('/b2b/v2/orders', xmlBody, 'application/xml', token);
```

- All methods accept an optional `token` string for `Authorization: Bearer` headers.
- `login(email, password)` returns `''` (empty string) on failure — never throws.
- For multipart file uploads or requests requiring custom headers not supported by the client, use the raw `request` fixture directly with the `BASE` constant defined locally.

### `AuthHelper` (`src/helpers/auth.helper.ts`)

```typescript
const auth = new AuthHelper(request);
const adminToken = await auth.loginAsAdmin();           // admin@juice-sh.op / admin123
const userToken  = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
```

- `AuthHelper.uniqueEmail()` returns a unique `test-<timestamp>@pwtest.local` address.
- Shared tokens must be acquired in `test.beforeAll` and reused across tests — never create a new `AuthHelper` inside an individual test if the describe block already has one.

## Test Writing Conventions

### Token setup

Acquire shared tokens once in `test.beforeAll`, not per-test:

```typescript
let adminToken: string;
let userToken: string;

test.beforeAll(async ({ request }) => {
  const auth = new AuthHelper(request);
  adminToken = await auth.loginAsAdmin();
  userToken  = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
});
```

### Parallel requests

Use `Promise.all` for independent HTTP requests — never sequential `for...of` loops:

```typescript
// ✓ correct
const statuses = await Promise.all(guesses.map(answer =>
  client.post('/rest/user/reset-password', { email, answer, new: pw, repeat: pw })
    .then(res => res.status())
));

// ✗ wrong — each request blocks the next
for (const answer of guesses) {
  const res = await client.post(...);
  statuses.push(res.status());
}
```

### Status code assertions

Prefer explicit allowlists over negative checks where possible:

```typescript
// ✓ clear intent
expect([401, 403].includes(res.status()), '...').toBe(true);

// ✗ accepts server errors as a pass
expect(res.status(), '...').not.toBe(200);
```

### XSS dialog detection

Use the `attachDialogDetector` closure pattern — attach before navigation, read after:

```typescript
function attachDialogDetector(page: Page): () => boolean {
  let fired = false;
  page.on('dialog', async (d) => { fired = true; await d.dismiss(); });
  return () => fired;
}

const xssExecuted = attachDialogDetector(page);
await page.goto(...);
await page.waitForLoadState('networkidle');
expect(xssExecuted(), 'XSS must not execute').toBe(false);
```

### Known selector notes

- Login error: `page.locator('div.error')` — Juice Shop uses `<div class="error">`, not `mat-error`.
- Search input: `page.locator('app-mat-search-bar input')` — `#searchQuery` resolves to the Angular component wrapper, not the native `<input>`.

## Allure Reporting

```bash
# Run tests (generates results)
npx playwright test

# Generate HTML report
npx allure generate reports/allure-results --clean -o reports/allure-report

# Serve report locally
npx allure open reports/allure-report
```

The Playwright reporter key is `resultsDir` (not `outputFolder`) — allure-playwright v3 renamed this option.
