import { type Page, type Locator } from '@playwright/test';
import { BasePage } from './base.page';

export class RegistrationPage extends BasePage {
  private readonly emailInput: Locator;
  private readonly passwordInput: Locator;
  private readonly repeatInput: Locator;
  private readonly registerButton: Locator;

  constructor(page: Page) {
    super(page);
    this.emailInput    = page.locator('#emailControl');
    this.passwordInput = page.locator('#passwordControl');
    this.repeatInput   = page.locator('#repeatPasswordControl');
    this.registerButton = page.locator('#registerButton');
  }

  public async navigate(): Promise<void> {
    await this.goto('/#/register');
  }

  public async register(email: string, password: string): Promise<void> {
    await this.emailInput.fill(email);
    await this.passwordInput.fill(password);
    await this.repeatInput.fill(password);
    await this.registerButton.click();
  }

  public async isRegisterButtonEnabled(): Promise<boolean> {
    return this.registerButton.isEnabled();
  }
}
