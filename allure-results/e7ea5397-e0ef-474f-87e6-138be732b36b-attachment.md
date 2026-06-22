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
Error: locator.click: Test timeout of 30000ms exceeded.
Call log:
  - waiting for locator('#loginButton')
    - locator resolved to <button type="submit" color="primary" id="loginButton" aria-label="Login" mat-raised-button="" _ngcontent-ng-c1122556316="" mat-ripple-loader-uninitialized="" mat-ripple-loader-class-name="mat-mdc-button-ripple" class="mdc-button mat-mdc-button-base mdc-button--raised mat-mdc-raised-button mat-primary">…</button>
  - attempting click action
    2 × waiting for element to be visible, enabled and stable
      - element is visible, enabled and stable
      - scrolling into view if needed
      - done scrolling
      - <a target="_blank" href="https://owasp-juice.shop">https://owasp-juice.shop</a> from <div class="cdk-overlay-container">…</div> subtree intercepts pointer events
    - retrying click action
    - waiting 20ms
    2 × waiting for element to be visible, enabled and stable
      - element is visible, enabled and stable
      - scrolling into view if needed
      - done scrolling
      - <a target="_blank" href="https://owasp-juice.shop">https://owasp-juice.shop</a> from <div class="cdk-overlay-container">…</div> subtree intercepts pointer events
    - retrying click action
      - waiting 100ms
    45 × waiting for element to be visible, enabled and stable
       - element is visible, enabled and stable
       - scrolling into view if needed
       - done scrolling
       - <a target="_blank" href="https://owasp-juice.shop">https://owasp-juice.shop</a> from <div class="cdk-overlay-container">…</div> subtree intercepts pointer events
     - retrying click action
       - waiting 500ms

```

# Page snapshot

```yaml
- generic:
  - dialog "cookieconsent" [ref=e1]:
    - generic [ref=e2]:
      - text: This website uses fruit cookies to ensure you get the juiciest tracking experience.
      - button "learn more about cookies" [ref=e3] [cursor=pointer]: But me wait!
    - button "dismiss cookie message" [ref=e5] [cursor=pointer]: Me want it!
  - generic [ref=e9]:
    - generic [ref=e12]:
      - button [ref=e13] [cursor=pointer]:
        - img [ref=e14]: menu
      - button [ref=e17]:
        - generic [ref=e19]:
          - img [ref=e20]
          - generic [ref=e21]: OWASP Juice Shop
      - generic [ref=e25]:
        - button [ref=e26] [cursor=pointer]:
          - img [ref=e27]: search
        - img [ref=e30]: search
        - textbox [ref=e31]
        - button [ref=e32] [cursor=pointer]:
          - img [ref=e33]: close
      - generic [ref=e36]:
        - button [ref=e37]:
          - img [ref=e38]: account_circle
          - generic [ref=e39]: Account
        - button [ref=e42]:
          - img [ref=e43]: shopping_cart
          - generic [ref=e44]:
            - text: Your Basket
            - generic [ref=e45]: "0"
        - button [ref=e48]:
          - img [ref=e49]: language
          - generic [ref=e50]: EN
    - generic [ref=e56]:
      - heading [level=1] [ref=e57]: Login
      - generic [ref=e58]:
        - generic [ref=e61]:
          - generic [ref=e62]:
            - text: Email
            - generic [ref=e63]: "*"
          - textbox [ref=e65]: notauser@test.com
        - generic [ref=e69]:
          - generic [ref=e70]:
            - text: Password
            - generic [ref=e71]: "*"
          - textbox [active] [ref=e73]: WrongPassword1!
          - button [ref=e75] [cursor=pointer]:
            - img [ref=e76]: eye
        - link [ref=e81] [cursor=pointer]:
          - /url: "#/forgot-password"
          - text: Forgot your password?
        - button [ref=e82]:
          - img [ref=e83]: exit_to_app
          - generic [ref=e84]: Log in
        - generic [ref=e88]:
          - generic [ref=e89] [cursor=pointer]:
            - checkbox [ref=e91]
            - generic:
              - img
          - generic [ref=e92] [cursor=pointer]: Remember me
        - generic [ref=e96]: or
        - button [ref=e99]:
          - generic [ref=e100]:
            - img [ref=e101]: google
            - text: Log in with Google
        - link [ref=e106] [cursor=pointer]:
          - /url: "#/register"
          - text: Not yet a customer?
  - dialog [ref=e111]:
    - generic [ref=e114]:
      - heading "Welcome to OWASP Juice Shop!" [level=1] [ref=e115]
      - generic [ref=e116]:
        - paragraph [ref=e117]:
          - text: Being a web application with a vast number of intended security vulnerabilities, the
          - strong [ref=e118]: OWASP Juice Shop
          - text: "is supposed to be the opposite of a best practice or template application for web developers: It is an awareness, training, demonstration and exercise tool for security risks in modern web applications. The"
          - strong [ref=e119]: OWASP Juice Shop
          - text: is an open-source project hosted by the non-profit
          - link "Open Worldwide Application Security Project (OWASP)" [ref=e120] [cursor=pointer]:
            - /url: https://owasp.org
          - text: and is developed and maintained by volunteers. Check out the link below for more information and documentation on the project.
        - heading "https://owasp-juice.shop" [level=1] [ref=e121]:
          - link "https://owasp-juice.shop" [ref=e122] [cursor=pointer]:
            - /url: https://owasp-juice.shop
      - generic [ref=e123]:
        - button "Help getting started" [ref=e124]:
          - img [ref=e125]: school
          - generic [ref=e126]: Help getting started
        - button "Close Welcome Banner" [ref=e129] [cursor=pointer]:
          - img [ref=e130]: visibility_off
          - generic [ref=e131]: Dismiss
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
> 32 |     await this.loginButton.click();
     |                            ^ Error: locator.click: Test timeout of 30000ms exceeded.
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
  47 |     return this.formError.innerText();
  48 |   }
  49 | 
  50 |   public async isLoginButtonEnabled(): Promise<boolean> {
  51 |     return this.loginButton.isEnabled();
  52 |   }
  53 | }
  54 | 
```