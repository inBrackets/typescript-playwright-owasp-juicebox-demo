import { Page, Response } from '@playwright/test';

export abstract class BasePage {
  protected readonly page: Page;

  constructor(page: Page) {
    this.page = page;
  }

  /** Each page is responsible for knowing its own route. */
  public abstract navigate(): Promise<void>;

  /** Waits for the Angular SPA to settle after navigation or user interaction. */
  protected async waitForPageLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
  }

  /**
   * Navigates to the given path and waits for the network to idle.
   * All subclass navigate() implementations should call this rather
   * than page.goto() directly so load-wait behaviour stays consistent.
   */
  protected async goto(path: string): Promise<Response | null> {
    const response = await this.page.goto(path);
    await this.waitForPageLoad();
    await this.dismissOverlays();
    return response;
  }

  // Juice Shop renders two overlays on every fresh page load that block all
  // underlying clicks: a welcome dialog and a cookie consent banner.
  // Both are silently ignored if absent (e.g. after session storage is set).
  private async dismissOverlays(): Promise<void> {
    await this.page
      .locator('button[aria-label="Close Welcome Banner"]')
      .click({ timeout: 3000 })
      .catch(() => undefined);

    await this.page
      .locator('a.cc-btn.cc-dismiss')
      .click({ timeout: 2000 })
      .catch(() => undefined);
  }

  public async getTitle(): Promise<string> {
    return this.page.title();
  }

  public async getCurrentUrl(): Promise<string> {
    return this.page.url();
  }
}
