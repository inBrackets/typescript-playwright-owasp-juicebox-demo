import { type Page, type Locator } from '@playwright/test';
import { BasePage } from './base.page';

export class ProductPage extends BasePage {
  public readonly reviewInput: Locator;
  public readonly submitReviewButton: Locator;
  public readonly reviews: Locator;

  constructor(page: Page) {
    super(page);
    this.reviewInput       = page.locator('#reviewControl, textarea[name="review"]');
    this.submitReviewButton = page.locator('#submitButton, button[aria-label="Submit"]');
    this.reviews           = page.locator('.review-text, mat-expansion-panel-header');
  }

  public async navigate(): Promise<void> {
    await this.goto('/#/');
  }

  public async navigateToProduct(productId: number): Promise<void> {
    await this.goto(`/#/product/${productId}`);
  }

  public async submitReview(text: string): Promise<void> {
    await this.reviewInput.fill(text);
    await this.submitReviewButton.click();
  }
}
