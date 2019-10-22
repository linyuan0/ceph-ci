import { Component, OnDestroy, OnInit } from '@angular/core';

import { I18n } from '@ngx-translate/i18n-polyfill';
import { BsModalRef, BsModalService } from 'ngx-bootstrap/modal';
import { Subscription } from 'rxjs';

import { RbdMirroringService } from '../../../../shared/api/rbd-mirroring.service';
import { Icons } from '../../../../shared/enum/icons.enum';
import { ViewCacheStatus } from '../../../../shared/enum/view-cache-status.enum';
import { CdTableAction } from '../../../../shared/models/cd-table-action';
import { CdTableSelection } from '../../../../shared/models/cd-table-selection';
import { Permission } from '../../../../shared/models/permissions';
import { AuthStorageService } from '../../../../shared/services/auth-storage.service';
import { EditSiteNameModalComponent } from '../edit-site-name-modal/edit-site-name-modal.component';

@Component({
  selector: 'cd-mirroring',
  templateUrl: './overview.component.html',
  styleUrls: ['./overview.component.scss']
})
export class OverviewComponent implements OnInit, OnDestroy {
  permission: Permission;
  tableActions: CdTableAction[];
  selection = new CdTableSelection();

  subs: Subscription;

  modalRef: BsModalRef;

  peersExist = true;
  siteName: any;
  status: ViewCacheStatus;

  constructor(
    private authStorageService: AuthStorageService,
    private rbdMirroringService: RbdMirroringService,
    private modalService: BsModalService,
    private i18n: I18n
  ) {
    this.permission = this.authStorageService.getPermissions().rbdMirroring;

    const editSiteNameAction: CdTableAction = {
      permission: 'update',
      icon: Icons.edit,
      click: () => this.editSiteNameModal(),
      name: this.i18n('Edit Site Name'),
      canBePrimary: () => true,
      disable: () => false
    };
    this.tableActions = [editSiteNameAction];
  }

  ngOnInit() {
    this.subs = this.rbdMirroringService.subscribeSummary((data: any) => {
      if (!data) {
        return;
      }
      this.status = data.content_data.status;
      this.siteName = data.site_name;

      this.peersExist = !!data.content_data.pools.find((o) => o['peer_uuids'].length > 0);
    });
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  editSiteNameModal() {
    const initialState = {
      siteName: this.siteName
    };
    this.modalRef = this.modalService.show(EditSiteNameModalComponent, { initialState });
  }
}
