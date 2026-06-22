import { type Page, type Locator } from '@playwright/test';
import { BasePage } from './base.page';

export class ComplaintPage extends BasePage {
  private readonly messageInput: Locator;
  private readonly fileInput: Locator;
  private readonly submitButton: Locator;

  constructor(page: Page) {
    super(page);
    this.messageInput = page.locator('#complaintMessage');
    this.fileInput    = page.locator('#file');
    this.submitButton = page.locator('#submitButton');
  }

  public async navigate(): Promise<void> {
    await this.goto('/#/complain');
  }

  public async fillMessage(text: string): Promise<void> {
    await this.messageInput.fill(text);
  }

  public async attachFile(path: string): Promise<void> {
    await this.fileInput.setInputFiles(path);
  }

  public async submit(): Promise<void> {
    await this.submitButton.click();
  }
}
