import { type Page, type Locator } from '@playwright/test';
import { BasePage } from './base.page';

export class ScoreboardPage extends BasePage {
  public readonly challengeCards: Locator;

  constructor(page: Page) {
    super(page);
    this.challengeCards = page.locator('mat-card, .challenge-card');
  }

  public async navigate(): Promise<void> {
    await this.goto('/#/score-board');
  }

  public async isVisible(): Promise<boolean> {
    return this.page.url().includes('score-board');
  }
}
