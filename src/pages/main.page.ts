import { Page, Locator } from '@playwright/test';
import { BasePage } from './base.page';
import { NavbarComponent } from '../components/navbar.component';

export class MainPage extends BasePage {
  /** Exposed for tests that drive global navigation from the home page. */
  public readonly navbar: NavbarComponent;

  private readonly productCards: Locator;

  constructor(page: Page) {
    super(page);
    this.navbar       = new NavbarComponent(page);
    this.productCards = page.locator('mat-card');
  }

  public async navigate(): Promise<void> {
    await this.goto('/#/');
  }

  public async getProductCount(): Promise<number> {
    return this.productCards.count();
  }
}
