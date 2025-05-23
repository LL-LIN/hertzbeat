/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { Message } from '../pojo/Message';
import { NoticeReceiver } from '../pojo/NoticeReceiver';
import { Page } from '../pojo/Page';

const notice_receiver_uri = '/notice/receiver';
const notice_receivers_uri = '/notice/receivers';
const notice_receivers_all_uri = '/notice/receivers/all';
const notice_receiver_send_test_msg_uri = '/notice/receiver/send-test-msg';

@Injectable({
  providedIn: 'root'
})
export class NoticeReceiverService {
  constructor(private http: HttpClient) {}

  public newReceiver(body: NoticeReceiver): Observable<Message<any>> {
    return this.http.post<Message<any>>(notice_receiver_uri, body);
  }

  public editReceiver(body: NoticeReceiver): Observable<Message<any>> {
    return this.http.put<Message<any>>(notice_receiver_uri, body);
  }

  public deleteReceiver(receiverId: number): Observable<Message<any>> {
    return this.http.delete<Message<any>>(`${notice_receiver_uri}/${receiverId}`);
  }

  public getReceivers(name: string, pageIndex: number, pageSize: number): Observable<Message<Page<NoticeReceiver>>> {
    pageIndex = pageIndex ? pageIndex : 0;
    pageSize = pageSize ? pageSize : 8;
    let httpParams = new HttpParams();
    httpParams = httpParams.append('pageIndex', pageIndex);
    httpParams = httpParams.append('pageSize', pageSize);
    if (name != undefined && name != null && name != '') {
      httpParams = httpParams.append('name', name);
    }
    const options = { params: httpParams };
    return this.http.get<Message<Page<NoticeReceiver>>>(notice_receivers_uri, options);
  }

  public getAllReceivers(): Observable<Message<NoticeReceiver[]>> {
    return this.http.get<Message<NoticeReceiver[]>>(notice_receivers_all_uri);
  }

  public getReceiver(receiverId: number): Observable<Message<NoticeReceiver>> {
    return this.http.get<Message<NoticeReceiver>>(`${notice_receiver_uri}/${receiverId}`);
  }

  public sendAlertMsgToReceiver(body: NoticeReceiver): Observable<Message<any>> {
    return this.http.post<Message<any>>(notice_receiver_send_test_msg_uri, body);
  }
}
