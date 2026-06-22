import { Page, Locator } from '@playwright/test';
import { BasePage } from './base.page';

export class LoginPage extends BasePage {
  private readonly emailInput: Locator;
  private readonly passwordInput: Locator;
  private readonly loginButton: Locator;
  private readonly formError: Locator;

  constructor(page: Page) {
    super(page);
    this.emailInput    = page.locator('#email');
    this.passwordInput = page.locator('#password');
    this.loginButton   = page.locator('#loginButton');
    // Juice Shop renders the server-side error in a <div class="error"> above the email field.
    this.formError     = page.locator('div.error');
  }

  public async navigate(): Promise<void> {
    await this.goto('/#/login');
  }

  public async fillEmail(email: string): Promise<void> {
    await this.emailInput.fill(email);
  }

  public async fillPassword(password: string): Promise<void> {
    await this.passwordInput.fill(password);
  }

  public async submit(): Promise<void> {
    await this.loginButton.click();
  }

  /**
   * Convenience method: fills credentials and submits.
   * Tests that need to assert intermediate field state should call the
   * individual fill/submit methods instead.
   */
  public async loginWith(email: string, password: string): Promise<void> {
    await this.fillEmail(email);
    await this.fillPassword(password);
    await this.submit();
  }

  public async getFormError(): Promise<string> {
    return (await this.formError.textContent()) ?? '';
  }

  public async isLoginButtonEnabled(): Promise<boolean> {
    return this.loginButton.isEnabled();
  }
}
