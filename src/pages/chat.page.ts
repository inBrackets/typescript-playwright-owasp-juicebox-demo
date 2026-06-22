import { type Page, type Locator } from '@playwright/test';
import { BasePage } from './base.page';

export class ChatPage extends BasePage {
  private readonly messageInput: Locator;
  private readonly sendButton: Locator;
  public readonly chatMessages: Locator;

  constructor(page: Page) {
    super(page);
    this.messageInput = page.locator('input[name="message"], #message, mat-form-field input').last();
    this.sendButton   = page.locator('button[type="submit"], #submitButton').last();
    this.chatMessages = page.locator('.bot-response, .chat-message, mat-list-item');
  }

  public async navigate(): Promise<void> {
    await this.goto('/#/chatbot');
  }

  public async sendMessage(text: string): Promise<void> {
    await this.messageInput.fill(text);
    await this.sendButton.click();
    await this.page.waitForTimeout(1500);
  }

  public async getLastResponse(): Promise<string> {
    return (await this.chatMessages.last().textContent()) ?? '';
  }
}
