import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const file=new URL('../cloudflare-worker.mjs',import.meta.url);
const source=fs.readFileSync(file,'utf8');
let connected=false;
const sandbox={Response,URL,TextEncoder,ArrayBuffer,Uint8Array,connect(){connected=true;throw Error('Network forbidden in guard tests')}};
vm.createContext(sandbox);
vm.runInContext(source.replace('import { connect } from "cloudflare:sockets";','').replace('export function isTelegramIp','function isTelegramIp').replace('export default {','globalThis.worker = {'),sandbox);
for (const ip of ['149.154.167.51','149.154.162.123','91.105.192.100']) assert.equal(vm.runInContext(`isTelegramIp(${JSON.stringify(ip)})`,sandbox),true);
for (const ip of ['127.0.0.1','192.168.1.1','10.0.0.1','169.254.169.254','8.8.8.8','1.2.3.4','149.154.175.256','149.154.167.1.attacker.test','149.154.0160.1','091.108.4.1']) assert.equal(vm.runInContext(`isTelegramIp(${JSON.stringify(ip)})`,sandbox),false);
for (const [path,upgrade,status] of [['/',false,426],['/other',true,404],['/apiws?dst=127.0.0.1',true,403],['/apiws?dst=8.8.8.8',true,403]]) {
 const request=new Request('https://test.invalid'+path,{headers:upgrade?{Upgrade:'websocket'}:{}});
 const response=await sandbox.worker.fetch(request);
 assert.equal(response.status,status);
}
assert.equal(connected,false);
console.log('Worker syntax and destination guards passed; tests opened no TCP connections.');
// Exercise the valid relay path with a runtime whose default binary type is Blob.
const writes=[]; const outgoing=[]; let accepted=false; let server;
class MockSocket {
 constructor(){this.binaryType='blob';this.listeners={};}
 accept(){assert.equal(this.binaryType,'arraybuffer');accepted=true;}
 addEventListener(type,handler){this.listeners[type]=handler;}
 send(data){outgoing.push([...data]);}
 close(){}
}
class MockPair { constructor(){this[0]={};this[1]=server=new MockSocket();} }
class MockResponse { constructor(body,options){Object.assign(this,options);this.body=body;} }
const relay={Response:MockResponse,URL,TextEncoder,ArrayBuffer,Uint8Array,WebSocketPair:MockPair,connect(target){
 assert.equal(target.hostname,'149.154.167.51');assert.equal(target.port,443);
 let reads=0;
 return {writable:{getWriter(){return {async write(bytes){writes.push([...bytes]);},async close(){}}}},readable:{getReader(){return {async read(){if(reads++===0)return {value:new Uint8Array([9,8]),done:false};return new Promise(()=>{});},releaseLock(){}}}},close(){}};
}};
vm.createContext(relay);
vm.runInContext(source.replace('import { connect } from "cloudflare:sockets";','').replace('export function isTelegramIp','function isTelegramIp').replace('export default {','globalThis.worker = {'),relay);
const liveResponse=await relay.worker.fetch(new Request('https://test.invalid/apiws?dst=149.154.167.51',{headers:{Upgrade:'websocket'}}));
assert.equal(liveResponse.status,101);assert.equal(accepted,true);
server.listeners.message({data:new Uint8Array([1,2]).buffer});
server.listeners.message({data:new Uint8Array([3]).buffer});
await new Promise(resolve=>setImmediate(resolve));
assert.deepEqual(writes,[[1,2],[3]]);assert.deepEqual(outgoing,[[9,8]]);
console.log('Binary compatibility, client-to-TCP order and TCP-to-client forwarding passed.');
