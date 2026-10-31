// Locks: project pages open with the project password; scripts are encrypted and open with the _s password.
// You shouldn't need to edit this file.
(async function(){
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const M=await (await fetch("vault/keys.json")).json();
const enc=new TextEncoder();
const ub=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const bu=b=>{let s="";const a=new Uint8Array(b);for(let i=0;i<a.length;i+=8192)s+=String.fromCharCode.apply(null,a.subarray(i,i+8192));return btoa(s)};
const SK="ad-keys";let keys={};try{keys=JSON.parse(sessionStorage.getItem(SK)||"{}")}catch(e){}
const save=()=>{try{sessionStorage.setItem(SK,JSON.stringify(keys))}catch(e){}};
const blobs={};
async function kek(pw){
  const base=await crypto.subtle.importKey("raw",enc.encode(pw.trim().toLowerCase()),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt:ub(M.salt),iterations:M.iter,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["decrypt"]);
}
async function tryPw(pw){
  if(!pw.trim())return -1;
  const k=await kek(pw);let n=0;
  for(const [id,it] of Object.entries(M.items)){
    if(keys[id])continue;
    for(const [iv,ct] of it.w){try{keys[id]=bu(await crypto.subtle.decrypt({name:"AES-GCM",iv:ub(iv)},k,ub(ct)));n++;break}catch(e){}}
  }
  save();return n;
}
async function openScript(id){
  const f=M.items[id+":script"].f;const r=await fetch(f);
  const b=f.endsWith(".txt")?ub((await r.text()).trim()):new Uint8Array(await r.arrayBuffer());
  const k=await crypto.subtle.importKey("raw",ub(keys[id+":script"]),"AES-GCM",false,["decrypt"]);
  return crypto.subtle.decrypt({name:"AES-GCM",iv:b.slice(0,12)},k,b.slice(12));
}
const projects=$$("section.proj").map(s=>s.dataset.id);
function renderFront(){
  $$(".cell").forEach(c=>{const id=c.getAttribute("href").slice(1);c.querySelector(".unl")?.remove();
    if(keys[id+":page"])c.querySelector(".ln").insertAdjacentHTML("beforeend",' <span class="hi unl">unlocked</span>')});
  const mf=$("#mform");if(mf)mf.hidden=projects.every(id=>keys[id+":page"]&&keys[id+":script"]);
}
async function renderProj(id){
  const s=$("#p-"+id),form=s.querySelector("form.pw-page"),open=s.querySelector(".open");
  form.querySelector(".msg").textContent="";form.querySelector("input[type=password]").value="";
  const isOpen=!!keys[id+":page"];form.hidden=isOpen;open.hidden=!isOpen;
  if(!isOpen)return;
  const slot=s.querySelector(".script"),name=slot.dataset.name;
  if(!keys[id+":script"]){
    slot.innerHTML=`<form class="pw-script"><label for="spw-${id}">script password:</label> <input id="spw-${id}" type="password" size="14" autocomplete="off"> <input type="submit" value="Submit"> <span class="msg" aria-live="polite"></span></form>`;
    slot.querySelector("form").addEventListener("submit",async e=>{e.preventDefault();const msg=e.target.querySelector(".msg");msg.textContent="checking…";
      const n=await tryPw(e.target.querySelector("input[type=password]").value);
      if(keys[id+":script"])renderProj(id);else msg.textContent=n<0?"type the password first.":"That's not it. Email me if you need it.";});
    return;
  }
  slot.innerHTML="<p>opening&hellip;</p>";
  try{
    if(!blobs[id])blobs[id]=URL.createObjectURL(new Blob([await openScript(id)],{type:"application/pdf"}));
    slot.innerHTML=`<p>&rarr; <a href="${blobs[id]}" target="_blank" rel="noopener">${name}</a> <span class="smol">(<a href="${blobs[id]}" download="${name}">download</a>)</span></p>`;
  }catch(e){slot.innerHTML="<p>Couldn't open the script. Reload the page and try again.</p>"}
}
function route(){
  const h=location.hash.slice(1),isP=projects.includes(h);
  $("#front").hidden=isP;$$("section.proj").forEach(s=>s.hidden=s.dataset.id!==h);
  if(isP)renderProj(h);else renderFront();
  window.scrollTo(0,0);
}
$$("form.pw-page").forEach(f=>f.addEventListener("submit",async e=>{
  e.preventDefault();const id=f.closest("section").dataset.id,msg=f.querySelector(".msg");msg.textContent="checking…";
  const n=await tryPw(f.querySelector("input[type=password]").value);
  if(keys[id+":page"])renderProj(id);else msg.textContent=n<0?"type the password first.":(n>0?"That opens a different project.":"That's not it. Email me if you need it.");
}));
$("#mform")?.addEventListener("submit",async e=>{
  e.preventDefault();const msg=e.target.querySelector(".msg");msg.textContent="checking…";
  const n=await tryPw($("#mpw").value);
  if(n<0)msg.textContent="type the password first.";else if(n===0)msg.textContent="That's not it. Email me if you need it.";
  else{msg.textContent="";$("#mpw").value="";renderFront();}
});
window.addEventListener("hashchange",route);
route();
})();
