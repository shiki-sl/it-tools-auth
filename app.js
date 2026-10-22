'use strict';
const $ = id => document.getElementById(id);
const labels = {cached_unverified:'缓存未过期 · 未向上游验证',cached:'缓存可用',expires_soon:'缓存临近到期',expired:'缓存已过期',refresh_available:'缓存已过期或即将到期 · 可尝试续期',refreshing:'正在刷新',authenticating:'正在登录',cooldown:'认证操作暂时冷却',login_required:'需要登录',cache_unavailable:'缓存不可安全读取',tool_unavailable:'认证助手不可用'};
const sources = {cache:'本地缓存',login:'上游登录',refresh:'上游刷新 / 续期'};
const errors = {
  executor_offline:'无法连接 9955HX 能力服务。操作结果可能不确定，请先更新状态，勿立即重复登录。',
  access_denied:'当前 Tailscale 身份或访问来源未获允许。',
  login_required:'需要登录。请展开“登录 / 重新登录”，输入当前账户密码后提交。',
  credentials_required:'没有可用的已有凭证。请在本页输入密码完成登录。',
  password_required:'请输入当前账户密码。密码仅用于本次网页登录。',
  refresh_unavailable:'当前环境或会话没有可用的免密续期方式，请使用网页登录。',
  refresh_failed:'续期未成功，请检查状态；需要时使用网页登录。',
  dns_failure:'9955HX 无法解析认证域名，请检查企业 DNS。',
  route_unreachable:'9955HX 无法连接认证服务，请检查 aTrust 和企业网络。',
  timeout:'认证服务响应超时，结果可能不确定。请先更新状态再决定是否重试。',
  authentication_failed:'认证未通过，请核对密码及企业认证状态后再操作。不会自动重试密码。',
  captcha_required:'上游要求验证码；请完成企业 SSO 验证码认证后再操作。本页不会绕过验证码。',
  mfa_required:'上游要求 MFA；请在企业认证渠道完成验证后再操作。本页不会绕过 MFA。',
  interaction_required:'上游需要额外认证。请完成企业 SSO 的验证码、MFA 或授权步骤后再操作。',
  interactive_required:'上游需要人工认证步骤。请打开企业 SSO，按实际要求完成认证后再操作；本页不会绕过。',
  protocol_changed:'上游认证响应不符合当前助手协议，无法确认成功；请检查认证助手与上游协议。',
  keyring_locked:'已有系统密钥环不可读取。可在本页临时输入密码，或先解锁 9955HX 密钥环。',
  http_error:'认证服务返回 HTTP 错误，响应正文未展示。',
  cache_unavailable:'缓存无法安全读取，请检查执行设备上的文件权限。',
  tool_unavailable:'执行设备缺少认证助手。',
  busy:'该环境已有认证请求进行中，请更新状态后再操作。',
  cooldown:'为避免重复登录，该环境暂时处于冷却期。',
  invalid_request:'请求格式未被接受，请更新页面后检查输入。',
  internal_error:'认证服务未能确认操作结果。请先更新状态；原始错误未展示。'
};
let token = '', tokenTimer, busy = false, statusBusy = false, privateGeneration = 0;
let environments = new Map();
function feedback(text, bad=false) { $('feedback').textContent=text; $('feedback').className=bad?'error':'success'; }
function clearToken() { token=''; $('token').value=''; $('token').type='password'; $('token-panel').hidden=true; $('reveal').textContent='显示 Token'; clearTimeout(tokenTimer); }
function clearPrivate() { privateGeneration++; clearToken(); $('password').value=''; }
async function api(path, body) {
  let response;
  try { response=await fetch(path, {method:body?'POST':'GET',cache:'no-store',credentials:'same-origin',redirect:'error',headers:body?{'Content-Type':'application/json','X-Workbench-Request':'1'}:{},body:body?JSON.stringify(body):undefined}); }
  catch { throw {code:'executor_offline'}; }
  finally { if(body && Object.hasOwn(body,'password')) body.password=''; }
  let data; try { data=await response.json(); } catch { throw {code:'internal_error'}; }
  if (!response.ok || !data.ok) throw {code:data.code||'internal_error',retryAfterSeconds:data.retryAfterSeconds};
  return data;
}
function date(value) { return typeof value==='number' && value>0?new Date(value*1000).toLocaleString('zh-CN'):'未知'; }
function seconds(value) { return Number.isFinite(value) && value>0?Math.ceil(value):0; }
function updateControls() {
  const state=environments.get($('env').value);
  const wait=state?seconds((state.cooldownUntil-Date.now())/1000):0;
  const unavailable=!state || ['cache_unavailable','tool_unavailable'].includes(state.state);
  const blocked=busy || ['refreshing','authenticating'].includes(state?.state);
  $('get-token').disabled=blocked || unavailable;
  $('renew-token').disabled=blocked || unavailable || wait>0 || state?.capabilities?.refresh!==true;
  $('login').disabled=blocked || unavailable || wait>0 || state?.capabilities?.login!==true;
  $('env').disabled=busy;
  $('password').disabled=busy;
  $('auth-section').setAttribute('aria-busy',String(busy));
  const rms=$('env').value.startsWith('rms-');
  if(state?.refreshRequiresLogin){
    $('capability').textContent='这份缓存的续期凭据已被上游拒绝，已停止重复刷新。可继续获取尚未过期的缓存；需要在本页重新登录后再续期。';
    return;
  }
  $('capability').textContent=!state?'环境能力尚未读取，请更新状态。':wait>0?`认证操作冷却中，约 ${wait} 秒后可重试；可尝试获取仍有效的缓存。`:state.capabilities?.refresh?(rms?'已接入网页登录与网关续期；当前缓存有会话凭据。刷新仅在访问令牌已过期且上游会话仍有效时签发新 Token，未到期返回缓存。':'已接入网页登录；当前缓存含刷新凭据，可尝试上游续期，实际结果以服务响应为准。'):(rms?'当前缺少 RMS 网关续期所需的会话凭据，请在本页登录；会话失效时也需重新登录。':'可使用网页登录；当前没有可用的 refreshToken，登录成功后按实际会话提供刷新。');
}
async function refreshStatus(silent=false) {
  if(statusBusy)return;
  statusBusy=true;$('refresh').disabled=true;
  try {
    const data=await api('/api/status');
    $('checked').textContent=`设备 ${data.device} · 读取时间 ${new Date(data.checkedAt).toLocaleString('zh-CN')}`;
    environments=new Map(data.environments.map(env=>[env.env,{...env,cooldownUntil:Date.now()+seconds(env.retryAfterSeconds)*1000}]));
    $('states').replaceChildren();
    for (const env of data.environments) {
      const card=document.createElement('article'), title=document.createElement('strong'), detail=document.createElement('p'), meta=document.createElement('small');
      title.textContent=env.env; detail.textContent=labels[env.state]||'状态未知'; meta.textContent=`缓存时间：${date(env.sourceTime)}；过期时间：${date(env.expiresAt)}`;
      card.append(title,detail,meta);
      if(seconds(env.retryAfterSeconds)) { const wait=document.createElement('small');wait.textContent=`本次读取时冷却剩余 ${seconds(env.retryAfterSeconds)} 秒`;card.append(wait); }
      const last=env.lastOperation;
      if(last && ['login','refresh','get'].includes(last.operation) && ['success','failure'].includes(last.result)) {
        const operation=document.createElement('small');
        const at=new Date(last.at);
        const outcome=last.result!=='success'?'未成功':last.operation==='refresh' && last.source==='cache'?'请求完成（返回缓存，未续期）':'成功';
        operation.textContent=`最近操作：${{login:'登录',refresh:'刷新',get:'获取'}[last.operation]}${outcome}${sources[last.source]?` · 来源 ${sources[last.source]}`:''}${Number.isNaN(at.getTime())?'':` · ${at.toLocaleString('zh-CN')}`}`;
        card.append(operation);
      }
      $('states').append(card);
    }
  } catch(e) { if(!silent)feedback(errors[e.code]||errors.internal_error,true); $('checked').textContent='当前状态不可读取；此前结果可能过期'; }
  finally {statusBusy=false;$('refresh').disabled=false;updateControls();}
}
function showToken(data) {
  if(typeof data.token!=='string'||!data.token)throw {code:'internal_error'};
  clearToken();token=data.token;$('token').value=token;$('token-panel').hidden=false;
  $('token-meta').textContent=`${data.env} · ${data.headerName}${data.headerPrefix?' / Bearer':''} · 到期 ${date(data.expiresAt)} · 来源：${sources[data.source]||'未确认'}`;
  const remaining=typeof data.expiresAt==='number'?data.expiresAt*1000-Date.now():300000;
  tokenTimer=setTimeout(()=>{clearToken();feedback('页面 Token 已到清除时限或已知到期时间。');},Math.max(0,Math.min(300000,remaining)));
}
async function operate(operation) {
  if(busy)return;
  const env=$('env').value, generation=privateGeneration, body={env};
  if(operation==='login') {
    body.password=$('password').value;$('password').value='';
    if(!body.password){feedback(errors.password_required,true);return;}
  }
  busy=true;updateControls();
  feedback(operation==='login'?'正在登录当前环境，请稍候…':operation==='refresh'?'正在请求上游刷新 / 续期，请稍候…':'正在获取当前 Token，请稍候…');
  try {
    const data=await api(`/api/${operation}`,body);
    if(generation!==privateGeneration)return;
    if(data.env!==env)throw {code:'internal_error'};
    showToken(data);
    feedback(`已获取 Token，来源：${sources[data.source]||'未确认'}。${operation==='refresh' && data.source==='cache'?'本次返回已有缓存，未签发新 Token，不代表续期成功。':''}未验证业务接口授权；Token 默认遮罩。`);
    if(operation==='login')$('login-details').open=false;
  } catch(e) {
    if(generation!==privateGeneration)return;
    if(seconds(e.retryAfterSeconds)) {
      const state=environments.get(env);if(state)state.cooldownUntil=Date.now()+seconds(e.retryAfterSeconds)*1000;
    }
    const wait=seconds(e.retryAfterSeconds);
    feedback((errors[e.code]||errors.internal_error)+(wait?` 请至少等待 ${wait} 秒。`:'')+(token?' 当前页面保留原 Token，可继续使用缓存；本次操作未确认成功，上游状态未确认。':''),true);
    if(['login_required','credentials_required','authentication_failed','refresh_unavailable'].includes(e.code))$('login-details').open=true;
  } finally {
    if(Object.hasOwn(body,'password'))body.password='';
    busy=false;updateControls();await refreshStatus(true);
  }
}
$('refresh').addEventListener('click',()=>refreshStatus());
$('env').addEventListener('change',()=>{clearPrivate();updateControls();feedback('已切换环境，并清除页面 Token 和密码。');});
$('get-token').addEventListener('click',()=>operate('token'));
$('renew-token').addEventListener('click',()=>operate('refresh'));
$('login-form').addEventListener('submit',event=>{event.preventDefault();if(!$('login').disabled)operate('login');});
$('reveal').addEventListener('click',()=>{const visible=$('token').type==='password';$('token').type=visible?'text':'password';$('reveal').textContent=visible?'隐藏 Token':'显示 Token';});
$('copy').addEventListener('click',async()=>{if(!token)return;try{await navigator.clipboard.writeText(token);feedback('Token 已复制到系统剪贴板。');}catch{feedback('剪贴板不可用，可显式显示后手动复制。',true);}});
$('clear').addEventListener('click',()=>{privateGeneration++;clearToken();feedback('已清除当前页面 Token。');});
window.addEventListener('pagehide',clearPrivate);
document.addEventListener('visibilitychange',()=>{if(document.hidden){$('token').type='password';$('reveal').textContent='显示 Token';}});
setInterval(updateControls,1000);
refreshStatus();
