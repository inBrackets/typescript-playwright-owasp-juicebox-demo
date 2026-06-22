import { Page, Locator } from '@playwright/test';

/**
 * Maps the Juice Shop top navigation bar (mat-toolbar).
 * Scoped to interactions that are available globally regardless of auth state.
 */
export class NavbarComponent {
  private readonly logoLink: Locator;
  private readonly searchToggleButton: Locator;
  private readonly searchInput: Locator;
  private readonly accountMenuButton: Locator;
  private readonly loginMenuItem: Locator;
  private readonly basketButton: Locator;

  constructor(page: Page) {
    this.logoLink           = page.locator('#navbarBrandLink');
    // aria-label is localised in some Juice Shop builds; match by icon content instead.
    this.searchToggleButton = page.locator('button').filter({ has: page.locator('mat-icon', { hasText: 'search' }) });
    this.searchInput        = page.locator('app-mat-search-bar input');
    this.accountMenuButton  = page.locator('#navbarAccount');
    this.loginMenuItem      = page.locator('#navbarLoginButton');
    this.basketButton       = page.locator('button[aria-label="Show the shopping cart"]');
  }

  public async goHome(): Promise<void> {
    await this.logoLink.click();
  }

  public async search(query: string): Promise<void> {
    await this.searchToggleButton.click();
    await this.searchInput.fill(query);
    await this.searchInput.press('Enter');
  }

  public async openAccountMenu(): Promise<void> {
    await this.accountMenuButton.click();
  }

  public async navigateToLogin(): Promise<void> {
    await this.openAccountMenu();
    await this.loginMenuItem.click();
  }

  public async openBasket(): Promise<void> {
    await this.basketButton.click();
  }

  /** Returns the visible text of the account button — useful for asserting login state. */
  public async getAccountButtonLabel(): Promise<string> {
    return this.accountMenuButton.innerText();
  }
}
