"use strict";
const csrf=document.body.dataset.csrf;
const filter=document.querySelector("#filter");
if(filter)filter.addEventListener("input",()=>{const q=filter.value.toLowerCase();document.querySelectorAll("#tunnels tbody tr[data-search]").forEach(row=>row.hidden=!row.dataset.search.toLowerCase().includes(q));});
document.querySelectorAll("time[data-epoch]").forEach(el=>{el.textContent=new Date(Number(el.dataset.epoch)*1000).toLocaleString();});
async function mutate(url,method,body){const headers={"X-CSRF-Token":csrf};if(body!==undefined)headers["Content-Type"]="application/json";const r=await fetch(url,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});if(!r.ok){const payload=await r.json().catch(()=>({}));throw new Error(payload?.error?.message||`HTTP ${r.status}`);}return r.json();}
document.querySelectorAll(".delete-tunnel").forEach(button=>button.addEventListener("click",async()=>{if(!confirm(`Delete ${button.dataset.id}? Active connections will close.`))return;button.disabled=true;try{await mutate(`/v1/admin/tunnels/${encodeURIComponent(button.dataset.id)}`,"DELETE");button.closest("tr").remove();}catch(error){alert(error.message);button.disabled=false;}}));
document.querySelectorAll(".toggle-ann").forEach(button=>button.addEventListener("click",async()=>{const row=button.closest("tr"),enabled=button.dataset.enabled!=="true";try{await mutate(`/v1/admin/announcements/${encodeURIComponent(row.dataset.id)}`,"PATCH",{enabled});button.dataset.enabled=String(enabled);button.textContent=enabled?"yes":"no";}catch(error){alert(error.message);}}));
document.querySelectorAll(".verify-ann").forEach(button=>button.addEventListener("click",async()=>{const row=button.closest("tr"),verified=button.dataset.verified!=="true";try{await mutate(`/v1/admin/announcements/${encodeURIComponent(row.dataset.id)}`,"PATCH",{verified});button.dataset.verified=String(verified);button.textContent=verified?"yes":"no";}catch(error){alert(error.message);}}));
document.querySelectorAll(".delete-ann").forEach(button=>button.addEventListener("click",async()=>{const row=button.closest("tr");if(!confirm(`Delete ${row.dataset.id}?`))return;try{await mutate(`/v1/admin/announcements/${encodeURIComponent(row.dataset.id)}`,"DELETE");row.remove();}catch(error){alert(error.message);}}));
document.querySelector("#logout")?.addEventListener("click",async()=>{try{await mutate("/v1/admin/logout","POST");location.href="/admin/login";}catch(error){alert(error.message);}});
async function topology(){const out=document.querySelector("#topology");try{const r=await fetch("/v1/admin/topology");if(!r.ok)throw new Error(`HTTP ${r.status}`);const data=await r.json();const lines=["BROKER"];for(const t of data.tunnels){lines.push(`├─ ${t.id} [${t.proto.toUpperCase()} ${t.closed?"closed":"open"}] ${t.agent_online?"online":"offline"}`);lines.push(`│  ├─ ${t.proto==="udp"?"flows":"streams"}: ${t.streams_active||0}`);for(const a of t.announcements)lines.push(`│  └─ ${a.service_name} (${a.id})`);}out.textContent=lines.join("\n");}catch(error){out.textContent=`topology unavailable: ${error.message}`;}}
document.querySelector("#refresh-topology")?.addEventListener("click",topology);topology();setInterval(topology,10000);

/* ---- system panel: SSE-driven tiles with inline sparklines ---------------- */
const tiles=document.querySelector("#system-tiles");
const sysStatus=document.querySelector("#system-status");
const history={};
const HISTORY_MAX=60;
function human(bytes){if(!bytes)return "0 B";const u=["B","KB","MB","GB","TB"];let i=0,v=Number(bytes);while(v>=1024&&i<u.length-1){v/=1024;i++;}return `${v.toFixed(v<10&&i>0?1:0)} ${u[i]}`;}
/* Inline sparkline as unicode blocks: no chart library for twelve tiles. */
const BLOCKS="▁▂▃▄▅▆▇█";
function spark(key,value,ceiling){const h=history[key]||(history[key]=[]);h.push(Number(value)||0);if(h.length>HISTORY_MAX)h.shift();const top=ceiling||Math.max(...h,1);return h.map(v=>BLOCKS[Math.min(BLOCKS.length-1,Math.max(0,Math.round(v/top*(BLOCKS.length-1))))]).join("");}
function setTile(key,text){const el=tiles?.querySelector(`b[data-k="${key}"]`);if(el)el.textContent=text;}
function setSpark(key,text){const el=tiles?.querySelector(`i[data-spark="${key}"]`);if(el)el.textContent=text;}
function renderSystem(s){
  if(!s||!tiles)return;
  const mem=s.memory||{},disk=s.disk||{},api=s.api||{},bp=s.broker_process||{},br=s.broker||{},rates=s.rates||{};
  setTile("cpu",`${s.cpu_percent??0}%`);setSpark("cpu",spark("cpu",s.cpu_percent,100));
  setTile("mem",`${mem.used_percent??0}% of ${human((mem.total_kib||0)*1024)}`);setSpark("mem",spark("mem",mem.used_percent,100));
  setTile("disk",`${disk.used_percent??0}% of ${human(disk.total_bytes)}`);
  setTile("load",(mem.load_average||[0])[0]);
  setTile("brss",human((bp.rss_kib||0)*1024));setSpark("brss",spark("brss",bp.rss_kib));
  setTile("bfd",bp.open_fds??"–");
  setTile("arss",human((api.rss_kib||0)*1024));
  setTile("rxr",`${human(rates.rx_bytes_total||0)}/s`);setSpark("rxr",spark("rxr",rates.rx_bytes_total));
  setTile("txr",`${human(rates.tx_bytes_total||0)}/s`);setSpark("txr",spark("txr",rates.tx_bytes_total));
  setTile("cps",(rates.conns_total??0).toFixed(1));
  setTile("rec",br.agent_reconnects??0);
  setTile("perr",br.protocol_errors??0);
}
async function primeSystem(){try{const r=await fetch("/v1/admin/system?history=60");if(!r.ok)return;const d=await r.json();(d.series||[]).forEach(renderSystem);}catch(e){/* stream will retry */}}
function streamSystem(){
  if(!tiles)return;
  const es=new EventSource("/v1/admin/system/stream");
  es.onopen=()=>{if(sysStatus)sysStatus.textContent="live";};
  es.onmessage=ev=>{try{renderSystem(JSON.parse(ev.data));}catch(e){}};
  /* EventSource reconnects on its own; surface the gap rather than hiding it. */
  es.onerror=()=>{if(sysStatus)sysStatus.textContent="reconnecting…";};
}
primeSystem().then(streamSystem);

/* ---- stream inspection --------------------------------------------------- */
const inspectDialog=document.querySelector("#inspect");
document.querySelectorAll(".inspect").forEach(button=>button.addEventListener("click",async()=>{
  const id=button.dataset.id;
  document.querySelector("#inspect-title").textContent=id;
  const body=document.querySelector("#inspect-body");
  body.textContent="loading…";
  inspectDialog?.showModal();
  try{
    const r=await fetch(`/v1/admin/tunnels/${encodeURIComponent(id)}/streams`);
    if(!r.ok)throw new Error(`HTTP ${r.status}`);
    const d=await r.json();
    const rt=d.runtime||{},t=d.tunnel||{};
    body.textContent=[
      `tunnel      ${t.tunnel_id}`,
      `protocol    ${d.protocol}   scope ${t.scope}`,
      `address     ${t.peer_address}`,
      `state       ${t.online?"online":"offline"}   enabled ${t.enabled}`,
      `${d.protocol==="udp"?"flows":"streams"}     active ${d.streams_active}  total ${d.streams_total}`,
      `bytes       rx ${rt.rx_bytes||0}  tx ${rt.tx_bytes||0}`,
      `datagrams   rx ${rt.datagrams_rx||0}  tx ${rt.datagrams_tx||0}`,
      `udp bytes   rx ${rt.udp_bytes_rx||0}  tx ${rt.udp_bytes_tx||0}`,
      `rejected    ${rt.conns_rejected_offline||0} while offline`,
      `created     ${new Date((t.created_at||0)*1000).toLocaleString()}`,
      `expires     ${new Date((t.expires_at||0)*1000).toLocaleString()}`,
    ].join("\n");
  }catch(error){body.textContent=`unavailable: ${error.message}`;}
}));
document.querySelector("#inspect-close")?.addEventListener("click",()=>inspectDialog?.close());
