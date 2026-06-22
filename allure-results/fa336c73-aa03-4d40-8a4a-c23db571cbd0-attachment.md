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
Error: locator.innerText: Test timeout of 30000ms exceeded.
Call log:
  - waiting for locator('mat-error')

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
  - generic [ref=e52]:
    - generic [ref=e53]:
      - text: "You successfully solved a challenge: Login Admin (Log in with the administrator's user account.)"
      - button "Jump to related coding challenge" [ref=e55] [cursor=pointer]:
        - img [ref=e56]: code
        - generic [ref=e57]: Jump to related coding challenge
    - button "X" [ref=e60]:
      - generic [ref=e61]: X
  - generic [ref=e67]:
    - heading "Login" [level=1] [ref=e68]
    - generic [ref=e69]: Invalid email or password.
    - generic [ref=e70]:
      - generic [ref=e73]:
        - generic [ref=e74]:
          - text: Email
          - generic [ref=e75]: "*"
        - textbox "Text field for the login email" [ref=e77]:
          - /placeholder: ""
          - text: notauser@test.com
      - generic [ref=e81]:
        - generic [ref=e82]:
          - text: Password
          - generic [ref=e83]: "*"
        - textbox "Text field for the login password" [ref=e85]:
          - /placeholder: ""
          - text: WrongPassword1!
        - button "Button to display the password" [ref=e87] [cursor=pointer]:
          - img [ref=e88]: eye
      - link "Forgot your password?" [ref=e93] [cursor=pointer]:
        - /url: "#/forgot-password"
      - button "Login" [active] [ref=e94]:
        - img [ref=e95]: exit_to_app
        - generic [ref=e96]: Log in
      - generic [ref=e100]:
        - generic [ref=e101] [cursor=pointer]:
          - checkbox "Checkbox to stay logged in or not logged in" [ref=e103]
          - generic:
            - img
        - generic [ref=e104] [cursor=pointer]: Remember me
      - generic [ref=e108]: or
      - button "Login with Google" [ref=e111]:
        - generic [ref=e112]:
          - img [ref=e113]: google
          - text: Log in with Google
      - link "Not yet a customer?" [ref=e118] [cursor=pointer]:
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
  15 |     // mat-error is the Angular Material validation message element
  16 |     this.formError     = page.locator('mat-error');
  17 |   }
  18 | 
  19 |   public async navigate(): Promise<void> {
  20 |     await this.goto('/#/login');
  21 |   }
  22 | 
  23 |   public async fillEmail(email: string): Promise<void> {
  24 |     await this.emailInput.fill(email);
  25 |   }
  26 | 
  27 |   public async fillPassword(password: string): Promise<void> {
  28 |     await this.passwordInput.fill(password);
  29 |   }
  30 | 
  31 |   public async submit(): Promise<void> {
  32 |     await this.loginButton.click();
  33 |   }
  34 | 
  35 |   /**
  36 |    * Convenience method: fills credentials and submits.
  37 |    * Tests that need to assert intermediate field state should call the
  38 |    * individual fill/submit methods instead.
  39 |    */
  40 |   public async loginWith(email: string, password: string): Promise<void> {
  41 |     await this.fillEmail(email);
  42 |     await this.fillPassword(password);
  43 |     await this.submit();
  44 |   }
  45 | 
  46 |   public async getFormError(): Promise<string> {
> 47 |     return this.formError.innerText();
     |                           ^ Error: locator.innerText: Test timeout of 30000ms exceeded.
  48 |   }
  49 | 
  50 |   public async isLoginButtonEnabled(): Promise<boolean> {
  51 |     return this.loginButton.isEnabled();
  52 |   }
  53 | }
  54 | 
```