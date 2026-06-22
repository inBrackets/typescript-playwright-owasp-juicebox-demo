# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: sqli.spec.ts >> SQL Injection – Authentication Bypass (OWASP A03:2021) >> login form must display an error on invalid credentials — not swallow them silently
- Location: src\tests\sqli.spec.ts:46:7

# Error details

```
Test timeout of 30000ms exceeded.
```

```
Error: locator.textContent: Test timeout of 30000ms exceeded.
Call log:
  - waiting for locator('mat-error').first()

```

# Page snapshot

```yaml
- generic [ref=e4]:
  - generic [ref=e7]:
    - button "Open Sidenav" [ref=e8] [cursor=pointer]:
      - img [ref=e9]: menu
    - button "Back to homepage" [ref=e12]:
      - generic [ref=e14]:
        - img "OWASP Juice Shop" [ref=e15]
        - generic [ref=e16]: OWASP Juice Shop
    - generic "Click to search" [ref=e20]:
      - button "Open search" [ref=e21] [cursor=pointer]:
        - img [ref=e22]: search
      - generic:
        - img [ref=e25]: search
        - textbox [ref=e26]
        - button "Close search" [ref=e27] [cursor=pointer]:
          - img [ref=e28]: close
    - generic [ref=e31]:
      - button "Show/hide account menu" [ref=e32]:
        - img [ref=e33]: account_circle
        - generic [ref=e34]: Account
      - button "Show the shopping cart" [ref=e37]:
        - img [ref=e38]: shopping_cart
        - generic [ref=e39]:
          - text: Your Basket
          - generic [ref=e40]: "0"
      - button "Language selection menu" [ref=e43]:
        - img [ref=e44]: language
        - generic [ref=e45]: EN
  - generic [ref=e51]:
    - heading "Login" [level=1] [ref=e52]
    - generic [ref=e53]: Invalid email or password.
    - generic [ref=e54]:
      - generic [ref=e57]:
        - generic [ref=e58]:
          - text: Email
          - generic [ref=e59]: "*"
        - textbox "Text field for the login email" [ref=e61]:
          - /placeholder: ""
          - text: notauser@test.com
      - generic [ref=e65]:
        - generic [ref=e66]:
          - text: Password
          - generic [ref=e67]: "*"
        - textbox "Text field for the login password" [ref=e69]:
          - /placeholder: ""
          - text: WrongPassword1!
        - button "Button to display the password" [ref=e71] [cursor=pointer]:
          - img [ref=e72]: eye
      - link "Forgot your password?" [ref=e77] [cursor=pointer]:
        - /url: "#/forgot-password"
      - button "Login" [active] [ref=e78] [cursor=pointer]:
        - img [ref=e79]: exit_to_app
        - generic [ref=e80]: Log in
      - generic [ref=e84]:
        - generic [ref=e85] [cursor=pointer]:
          - checkbox "Checkbox to stay logged in or not logged in" [ref=e87]
          - generic:
            - img
        - generic [ref=e88] [cursor=pointer]: Remember me
      - generic [ref=e92]: or
      - button "Login with Google" [ref=e95]:
        - generic [ref=e96]:
          - img [ref=e97]: google
          - text: Log in with Google
      - link "Not yet a customer?" [ref=e102] [cursor=pointer]:
        - /url: "#/register"
```

# Test source

```ts
  1  | import { Page, Locator } from '@playwright/test';
  2  | import { BasePage } from './base.page';
  3  | 
  4  | export class LoginPage extends BasePage {
  5  |   private readonly emailInput: Locator;
  6  |   private readonly passwordInput: Locator;
  7  |   private readonly loginButton: Locator;
  8  |   private readonly formError: Locator;
  9  | 
  10 |   constructor(page: Page) {
  11 |     super(page);
  12 |     this.emailInput    = page.locator('#email');
  13 |     this.passwordInput = page.locator('#password');
  14 |     this.loginButton   = page.locator('#loginButton');
  15 |     // Juice Shop renders the server-side error in a standalone mat-error above the email field.
  16 |     // Angular Material MDC wraps it in an opacity-animated container, so innerText() (which
  17 |     // requires layout visibility) times out. textContent() reads the DOM regardless of CSS.
  18 |     this.formError     = page.locator('mat-error').first();
  19 |   }
  20 | 
  21 |   public async navigate(): Promise<void> {
  22 |     await this.goto('/#/login');
  23 |   }
  24 | 
  25 |   public async fillEmail(email: string): Promise<void> {
  26 |     await this.emailInput.fill(email);
  27 |   }
  28 | 
  29 |   public async fillPassword(password: string): Promise<void> {
  30 |     await this.passwordInput.fill(password);
  31 |   }
  32 | 
  33 |   public async submit(): Promise<void> {
  34 |     await this.loginButton.click();
  35 |   }
  36 | 
  37 |   /**
  38 |    * Convenience method: fills credentials and submits.
  39 |    * Tests that need to assert intermediate field state should call the
  40 |    * individual fill/submit methods instead.
  41 |    */
  42 |   public async loginWith(email: string, password: string): Promise<void> {
  43 |     await this.fillEmail(email);
  44 |     await this.fillPassword(password);
  45 |     await this.submit();
  46 |   }
  47 | 
  48 |   public async getFormError(): Promise<string> {
> 49 |     return (await this.formError.textContent()) ?? '';
     |                                  ^ Error: locator.textContent: Test timeout of 30000ms exceeded.
  50 |   }
  51 | 
  52 |   public async isLoginButtonEnabled(): Promise<boolean> {
  53 |     return this.loginButton.isEnabled();
  54 |   }
  55 | }
  56 | 
```