import { type Page, type Locator } from '@playwright/test';
import { BasePage } from './base.page';

export class FeedbackPage extends BasePage {
  private readonly commentInput: Locator;
  private readonly ratingStars: Locator;
  private readonly submitButton: Locator;

  constructor(page: Page) {
    super(page);
    this.commentInput = page.locator('#comment');
    this.ratingStars  = page.locator('.star-rating-blank');
    this.submitButton = page.locator('#submitButton');
  }

  public async navigate(): Promise<void> {
    await this.goto('/#/contact');
  }

  public async fillComment(text: string): Promise<void> {
    await this.commentInput.fill(text);
  }

  public async setRating(stars: number): Promise<void> {
    await this.ratingStars.nth(stars - 1).click();
  }

  public async submit(): Promise<void> {
    await this.submitButton.click();
  }
}
