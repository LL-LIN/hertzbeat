import { ChangeDetectionStrategy, Component } from '@angular/core';
import { Router } from '@angular/router';
import { SettingsService, User } from '@delon/theme';

import { LocalStorageService } from '../../../service/local-storage.service';
import { CONSTANTS } from '../../../shared/constants';

@Component({
  selector: 'header-user',
  template: `
    <div class="alain-default__nav-item d-flex align-items-center px-sm" nz-dropdown nzPlacement="bottomRight" [nzDropdownMenu]="userMenu">
      <nz-avatar [nzSrc]="user.avatar" nzSize="small" class="mr-sm"></nz-avatar>
      {{ user.name }}
    </div>
    <nz-dropdown-menu #userMenu="nzDropdownMenu">
      <div nz-menu class="width-sm">
        <div nz-menu-item routerLink="/setting/settings/config">
          <i nz-icon nzType="tool" class="mr-sm"></i>
          {{ 'menu.extras.setting' | i18n }}
        </div>
        <div nz-menu-item (click)="logout()">
          <i nz-icon nzType="logout" class="mr-sm"></i>
          {{ 'menu.account.logout' | i18n }}
        </div>
        <div nz-menu-item (click)="showAboutModal()">
          <i nz-icon nzType="environment" class="mr-sm"></i>
          {{ 'menu.extras.about' | i18n }}
        </div>
      </div>
    </nz-dropdown-menu>
  `,
  changeDetection: ChangeDetectionStrategy.Default
})
export class HeaderUserComponent {
  isAboutModalVisible = false;
  version = CONSTANTS.VERSION;
  currentYear = new Date().getFullYear();
  get user(): User {
    return this.settings.user;
  }

  constructor(private settings: SettingsService, private router: Router, private localStorageSvc: LocalStorageService) {
    // @ts-ignore
    if (router.getCurrentNavigation()?.previousNavigation?.finalUrl.toString() === '/passport/login') {
      this.showAndCloseAboutModal();
    }
  }

  logout(): void {
    this.localStorageSvc.clear();
    this.router.navigateByUrl('/passport/login');
  }

  showAboutModal() {
    this.isAboutModalVisible = true;
  }

  disAboutModal() {
    this.isAboutModalVisible = false;
  }

  showAndCloseAboutModal() {
    this.isAboutModalVisible = true;
    setTimeout(() => (this.isAboutModalVisible = false), 20000);
  }
}
