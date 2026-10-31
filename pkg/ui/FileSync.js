/* Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved. */
SYNO.namespace('SYNO.SDS.App.FileSync');

function fileSyncTokenFromResponse(result) {
  var data = result && result.data ? result.data : result;
  if (!result || result.success === false) return '';
  return (data && (data.synotoken || data.SynoToken || data.token)) ||
    result.SynoToken || result.synotoken || '';
}

function fileSyncTokenFromDsmContext() {
  var token = '';
  try {
    token = window.SYNO && SYNO.SDS && SYNO.SDS.Session && SYNO.SDS.Session.SynoToken;
  } catch (e) {}
  if (!token) {
    try { token = new URLSearchParams(window.location.search).get('SynoToken'); } catch (e) {}
  }
  return typeof token === 'string' ? token : '';
}

function fileSyncFetchToken(url) {
  return fetch(url, { credentials: 'same-origin', cache: 'no-store' })
    .then(function (response) { return response.json(); })
    .then(fileSyncTokenFromResponse)
    .catch(function () { return ''; });
}

SYNO.SDS.App.FileSync.Instance = Vue.extend({
  data: function () { return { cgiUrl: 'about:blank' }; },
  created: function () {
    var vm = this;
    var token = fileSyncTokenFromDsmContext();
    var getApiToken = function () {
      return fileSyncFetchToken('/webapi/entry.cgi?api=SYNO.API.Auth&version=6&method=token');
    };
    Promise.resolve(token || getApiToken()).then(function (value) {
      return value || fileSyncFetchToken('/webman/login.cgi');
    }).then(function (value) {
      vm.cgiUrl = '/webman/3rdparty/FileSync/index.cgi' +
        (value ? '?SynoToken=' + encodeURIComponent(value) : '');
    }).catch(function () {
      // CGI 仍会在服务端校验 DSM Cookie；无法取到 token 时直接打开，由服务端决定是否拒绝。
      vm.cgiUrl = '/webman/3rdparty/FileSync/index.cgi';
    });
  },
  template: '<v-app-instance class-name="SYNO.SDS.App.FileSync.Instance">' +
    '<v-app-window syno-id="SYNO.SDS.App.FileSync.Window" width="1240" height="800" :resizable="true">' +
    '<iframe title="多站文件同步" :src="cgiUrl" style="width:100%;height:100%;border:0;display:block"></iframe>' +
    '</v-app-window></v-app-instance>'
});
