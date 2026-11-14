// @vitest-environment jsdom
// Synthetic IPC exercises the human confirmation boundary; it is not a network proof.
import { act, createElement as h } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { beforeEach, afterEach, expect, it, vi } from 'vitest';
import { call } from '../src/ipc/client';
import { t } from '../src/copy';
import { AppContext, type AppApi } from '../src/ui/app';
import { personalRequestGroups, RequestCard } from '../src/screens/devices/AddMacDialog';
import { JoinMacDialog } from '../src/screens/devices/JoinMacDialog';
import { usePairJoin, type PairJoin } from '../src/screens/devices/usePairJoin';
import { encodePairingCode } from '../src/lib/pairing';
import type { JoinRequest, PairingJoinResult } from '../src/ipc/contract';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
vi.mock('../src/ipc/client', async (original) => ({ ...await original<typeof import('../src/ipc/client')>(), call: vi.fn(), on: vi.fn(async () => () => undefined) }));
const ipc=vi.mocked(call);
const A='faaaaaaaaaaaaaaaaaaaaaaaaa', B='fbbbbbbbbbbbbbbbbbbbbbbbbb';
const AKEY='a'.repeat(64), BKEY='b'.repeat(64), CHANGED='c'.repeat(64);
const PASS='synthetic-bootstrap-reauthentication';
const app:AppApi={desktop:true,toast:vi.fn(),announce:vi.fn(),locale:'en',language:'en',setLanguage:async()=>undefined};
const code=encodePairingCode({v:1,service:'https://link.example.org',link_token:'zplt_synthetic',peer:'a'.repeat(26),name:'original Mac',invites:[{env:'personal/vault',invite:'zeropw://join#'+'a'.repeat(80)}]});
const preview={name:'original Mac',peer:'a'.repeat(26),fingerprint:A,environments:[{env:'personal/vault',env_id:'synthetic',role:'admin'}],service:'https://link.example.org',service_host:'link.example.org',expires_at:new Date(Date.now()+600_000).toISOString()};
let host:HTMLDivElement,root:Root,pair:PairJoin;
const joined=vi.fn();
function Harness(){pair=usePairJoin(joined);return h(JoinMacDialog,{open:true,pj:pair,onClose:()=>undefined});}
const row=(binding=BKEY,request='request-1',env='personal/vault'):JoinRequest=>({env,request_id:request,invite_id:'invite-1',fingerprint:B,first_seen_at:1,last_seen_at:2,attempts:1,record_binding:binding,device_record:{sign_pub:'synthetic-same-signing-key',agree_pub:binding,sig:'synthetic-binding-signature'}});
const pending=(other=AKEY):PairingJoinResult=>({done:false,peer:preview.peer,environments:[{env:'personal/vault',state:'pending',bootstrap_state:'approval_pending',local_approval_complete:false,self_fingerprint:B,inviter_fingerprint:A,self_record_binding:BKEY,inviter_record_binding:other}]});
async function render(element:ReturnType<typeof h>){await act(async()=>root.render(h(AppContext,{value:app},element)));}
async function flush(){await act(async()=>{await Promise.resolve();});}
async function input(element:HTMLInputElement,value:string){await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')!.set!.call(element,value);element.dispatchEvent(new Event('input',{bubbles:true}));});}
async function start(){await render(h(Harness));await act(async()=>pair.setText(code));await flush();await act(async()=>pair.start());await flush();}
const calls=(name:string)=>ipc.mock.calls.filter(([command])=>command===name).map(([,value])=>value as Record<string,unknown>);

beforeEach(()=>{vi.useFakeTimers();vi.clearAllMocks();host=document.createElement('div');document.body.append(host);root=createRoot(host);ipc.mockImplementation((async(name:string)=>{if(name==='secure_view')return {protected:false};if(name==='onetime_discard')return undefined;if(name==='pairing_preview')return {ref:'personal-code',preview};throw {reason:'unexpected_test_command'};}) as never);});
afterEach(async()=>{await act(async()=>root.unmount());host.remove();document.body.querySelectorAll('[data-dialog-layer]').forEach((node)=>node.remove());vi.useRealTimers();});

it('keeps same-signing/different-agreement requests separate and makes polling stable',()=>{
  const first=row(),other=row(CHANGED,'request-2'),retry={...first,attempts:5};
  expect(personalRequestGroups([first,other])).toHaveLength(2);
  expect(personalRequestGroups([first])[0]!.key).toBe(personalRequestGroups([retry])[0]!.key);
  expect(personalRequestGroups([first])[0]!.key).not.toBe(personalRequestGroups([row(BKEY,'replacement')])[0]!.key);
  const combined=personalRequestGroups([first,row(BKEY,'request-3','work/dev')]);
  expect(combined).toHaveLength(1);expect(combined[0]!.requests.map((r)=>r.request_id)).toEqual(['request-1','request-3']);
});

it('submits the exact displayed full record and requires reauthentication after a changed request',async()=>{
  ipc.mockImplementation((async(name:string)=>name==='approve_join'?{fingerprint:B,envs:[{env:'personal/vault',ok:true}]}:{protected:false}) as never);
  const decided=vi.fn();
  const cards=(requests:JoinRequest[])=>h('div',null,...personalRequestGroups(requests).map((g)=>h(RequestCard,{key:g.key,fingerprint:g.fingerprint,envs:g.envs,attempts:g.attempts,personalRequests:g.requests,onDecided:decided})));
  await render(cards([row()]));
  expect(host.textContent).toContain(BKEY);
  const password=()=>host.querySelector<HTMLInputElement>('input[type="password"]')!;
  await input(password(),PASS);
  await render(cards([row(CHANGED,'request-2')]));
  expect(password().value).toBe('');expect(host.textContent).toContain(CHANGED);
  const approve=()=>[...host.querySelectorAll<HTMLButtonElement>('button')].find((b)=>b.textContent===t('mac.req.approve'))!;
  await act(async()=>approve().click());expect(calls('approve_join')).toHaveLength(0);
  await input(password(),PASS);await act(async()=>approve().click());
  expect(calls('approve_join')).toEqual([{envs:['personal/vault'],fingerprint:B,requests:[{env:'personal/vault',request_id:'request-2',record_binding:CHANGED}],admin_passphrase:PASS}]);
  expect(decided).toHaveBeenCalledWith(true);expect(password().value).toBe('');
});

it('shows both full bindings, reauthenticates B, and never reports joined at admission',async()=>{
  let durable=false;
  ipc.mockImplementation((async(name:string,value:unknown)=>{
    if(name==='pairing_preview')return {ref:'personal-code',preview};
    if(name==='pairing_join'){
      const request=value as {action?:string};
      if(request.action==='approve')return {...pending(),environments:[{...pending().environments[0]!,bootstrap_state:'transferring',local_approval_complete:true}]};
      return durable?{done:true,peer:preview.peer,environments:[{...pending().environments[0]!,state:'joined',bootstrap_state:'installed_syncing',local_approval_complete:true}]}:pending();
    }
    if(name==='secure_view')return {protected:false};return undefined;
  }) as never);
  await start();expect(document.body.textContent).toContain(AKEY);expect(document.body.textContent).toContain(BKEY);expect(joined).not.toHaveBeenCalled();
  await act(async()=>pair.setApprovalPass(PASS));await act(async()=>pair.approve());
  expect(calls('pairing_join').find((v)=>v.action==='approve')).toEqual({ref:'personal-code',action:'approve',bindings:[{env:'personal/vault',record_binding:AKEY,self_record_binding:BKEY}],admin_passphrase:PASS});
  expect(joined).not.toHaveBeenCalled();expect(pair.phase.kind).toBe('waiting');
  durable=true;await act(async()=>{await vi.advanceTimersByTimeAsync(3010);});expect(joined).toHaveBeenCalledTimes(1);expect(pair.phase.kind).toBe('done');
});

it('clears B reauthentication when the displayed agreement binding changes',async()=>{
  let other=AKEY;
  ipc.mockImplementation((async(name:string)=>name==='pairing_preview'?{ref:'personal-code',preview}:name==='pairing_join'?pending(other):{protected:false}) as never);
  await start();await act(async()=>pair.setApprovalPass(PASS));other=CHANGED;
  await act(async()=>{await vi.advanceTimersByTimeAsync(3010);});expect(pair.approvalPass).toBe('');
  await act(async()=>pair.approve());expect(calls('pairing_join').filter((v)=>v.action==='approve')).toHaveLength(0);
});

it('cancels a durable personal attempt before discarding a reference, including an in-flight first poll',async()=>{
  let resolve!:(v:PairingJoinResult)=>void;
  const first=new Promise<PairingJoinResult>((done)=>{resolve=done;});
  ipc.mockImplementation((async(name:string,value:unknown)=>{
    if(name==='pairing_preview')return {ref:'personal-code',preview};
    if(name==='pairing_join')return (value as {action?:string}).action==='cancel'?pending():first;
    if(name==='secure_view')return {protected:false};return undefined;
  }) as never);
  await start();await act(async()=>pair.cancel());expect(calls('onetime_discard')).toHaveLength(0);
  await act(async()=>resolve(pending()));await flush();
  expect(calls('pairing_join').some((v)=>v.action==='cancel')).toBe(true);expect(calls('onetime_discard')).toEqual([{ref:'personal-code'}]);expect(joined).not.toHaveBeenCalled();
});
