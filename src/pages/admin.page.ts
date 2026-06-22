import { type Page, type Locator } from '@playwright/test';
import { BasePage } from './base.page';

export class AdminPage extends BasePage {
  public readonly userTable: Locator;

  constructor(page: Page) {
    super(page);
    this.userTable = page.locator('mat-table, .user-table, table');
  }

  public async navigate(): Promise<void> {
    await this.goto('/#/administration');
  }

  public async getCurrentPath(): Promise<string> {
    const url = new URL(this.page.url());
    return url.hash;
  }
}
