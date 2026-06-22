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
- Each vulnerability test must document the **CVE or OWASP category** it targets in a `@tag` or inline comment.
- Security regression tests belong in `tests/security/`. Functional smoke tests belong in `tests/functional/`.

## Project Structure

```
src/
  pages/          # POM page classes
  components/     # COM component classes
  fixtures/       # Playwright fixture extensions
  helpers/        # Auth, API, and shared utilities
tests/
  functional/     # Functional regression tests
  security/       # Security regression tests (SQLi, XSS, etc.)
```
