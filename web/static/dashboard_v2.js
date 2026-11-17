/* HIDS Guard dashboard — visualizes real /api/dashboard/analytics results only. */
(() => {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const $ = id => document.getElementById(id);
  const palette = {High:'#ef7077', Medium:'#f2ba49', Low:'#629bff', Total:'#9b8cfb',
                   Open:'#b89cff', InputTap:'#51c5df', Persistence:'#e3ad5f', Scans:'#76a5fb', Visibility:'#39cda1'};
  let busy = false;
  let selectedDevice = '';
  const svgNode = (name, attrs={}, value=null) => {
    const n=document.createElementNS(NS,name);
    for(const [k,v] of Object.entries(attrs)) n.setAttribute(k,String(v));
    if(value!==null)n.textContent=String(value);
    return n;
  };
  const append = (parent,name,attrs={},value=null) => {
    const node=svgNode(name,attrs,value);parent.appendChild(node);return node;
  };
  const clamp=(a,lo,hi)=>Math.min(hi,Math.max(lo,a));
  const fmtTime = ts => ts ? new Date(ts*1000).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}) : 'Never';
  const fmtLabel=(ts,selection)=>{
    const d=new Date(ts*1000);
    return selection==='24h'?d.toLocaleTimeString(undefined,{hour:'numeric'}):d.toLocaleDateString(undefined,{month:'short',day:'numeric'});
  };
  const simplify = value => (value||'').replace(/_/g,' ').toLowerCase().replace(/\b\w/g, s=>s.toUpperCase());
  function spark(id,values,color){
    const root=$(id);if(!root)return;root.replaceChildren();
    const n=values.length||1,max=Math.max(1,...values),W=180,H=31,pad=2;
    const xy=values.map((v,i)=>[pad+(n===1?0:i*(W-pad*2)/(n-1)),H-4-(v/max)*(H-11)]);
    const path=xy.map(([x,y],i)=>(i?'L':'M')+x.toFixed(1)+' '+y.toFixed(1)).join(' ');
    if(!path)return;
    const fill=path+` L${xy[xy.length-1][0]} ${H} L${xy[0][0]} ${H} Z`;
    append(root,'path',{d:fill,fill:color,opacity:'.13'});
    append(root,'path',{d:path,fill:'none',stroke:color,'stroke-width':'1.8','stroke-linecap':'round','stroke-linejoin':'round'});
  }
  function grid(root,max,{x=38,y=12,w=364,h=188}={}){
    for(let j=0;j<=4;j++){
      const yy=y+j*h/4;
      append(root,'line',{x1:x,x2:x+w,y1:yy,y2:yy,stroke:'#40506a','stroke-width':1,opacity:.75});
      append(root,'text',{x:x-9,y:yy+4,'text-anchor':'end','font-size':11,fill:'#8496b2'},Math.round(max*(1-j/4)));
    }
  }
  function view(svg,labels,period){
    const n=labels.length;
    if(!n)return;
    const every=n>14?Math.ceil(n/5):1;
    labels.forEach((ts,i)=>{
      if(i%every!==0&&i!==n-1)return;
      const x=38+(i+.5)*364/n;
      append(svg,'text',{x,y:225,'font-size':10,'text-anchor':'middle',fill:'#8fa3be'},fmtLabel(ts,period));
    });
  }
  function severityChart(d){
    const root=$('chart-severity');root.replaceChildren();
    const {High,Medium,Low}=d.series;
    const totals=High.map((_,i)=>High[i]+Medium[i]+Low[i]);
    const max=Math.max(1,...totals);
    grid(root,max);
    const n=totals.length,slot=364/n,width=clamp(slot*.58,4,33);
    for(let i=0;i<n;i++){
      let bottom=200;
      for(const key of ['Low','Medium','High']){
        const value=d.series[key][i];if(!value)continue;
        const height=value/max*188;
        append(root,'rect',{x:38+(i+.5)*slot-width/2,y:bottom-height,width,height,fill:palette[key],rx:1});
        bottom-=height;
      }
    }
    view(root,d.buckets,d.range);
    if(totals.every(x=>x===0))append(root,'text',{x:215,y:115,'text-anchor':'middle','font-size':13,fill:'#a8b6d0'},'No alerts in this period');
  }
  function line(root,arr,max,color){
    const len=arr.length;if(!len)return;
    const point=(v,i)=>[38+(i+.5)*364/len,200-v/max*188];
    const points=arr.map(point);
    const d=points.map(([x,y],i)=>(i?'L':'M')+x.toFixed(2)+' '+y.toFixed(2)).join(' ');
    append(root,'path',{d,stroke:color,'stroke-width':2.5,fill:'none','stroke-linejoin':'round','stroke-linecap':'round'});
    points.forEach(([x,y],i)=>{if(len<=7||i===len-1)append(root,'circle',{cx:x,cy:y,r:3,fill:color});});
  }
  function timelineChart(d){
    const root=$('chart-timeline');root.replaceChildren();
    const a=d.series.Total,b=d.series.High,max=Math.max(1,...a);
    grid(root,max);line(root,a,max,palette.Total);line(root,b,max,palette.High);
    view(root,d.buckets,d.range);
    if(a.every(v=>v===0))append(root,'text',{x:215,y:115,'text-anchor':'middle','font-size':13,fill:'#a8b6d0'},'No new alerts in this period');
  }
  function ruleChart(d){
    const root=$('chart-rules');root.replaceChildren();
    if(!d.rules.length){const empty=document.createElement('div');empty.className='v2-empty';empty.textContent='No detection-rule hits in the selected period.';root.appendChild(empty);return;}
    const max=Math.max(1,...d.rules.map(r=>r.count));
    for(const rule of d.rules){
      const row=document.createElement('div');row.className='v2-rule-row';
      const label=document.createElement('span');label.className='v2-rule-label';label.textContent=simplify(rule.name);label.title=rule.name;
      const track=document.createElement('div');track.className='v2-rule-track';
      const bar=document.createElement('i');bar.style.width=(rule.count/max*100)+'%';track.appendChild(bar);
      const n=document.createElement('b');n.textContent=String(rule.count);
      row.append(label,track,n);root.appendChild(row);
    }
  }
  function recent(d){
    const root=$('recent-alerts');root.replaceChildren();
    if(!d.recent.length){const row=document.createElement('tr'),td=document.createElement('td');td.colSpan=5;td.textContent='No security alerts first observed in the selected period.';row.appendChild(td);root.appendChild(row);return;}
    for(const item of d.recent){
      const tr=document.createElement('tr');
      const name=document.createElement('td');name.textContent=item.subject||'Unknown';name.title=item.subject||'';
      const sev=document.createElement('td');const label=document.createElement('span');label.className='v2-sev '+item.severity;label.textContent=item.severity;sev.appendChild(label);
      const status=document.createElement('td');status.textContent=item.status;
      const seen=document.createElement('td');seen.textContent=fmtTime(item.last_seen);
      const action=document.createElement('td');const a=document.createElement('a');a.href='/alert/'+encodeURIComponent(item.id);a.textContent='Review →';action.appendChild(a);
      tr.append(name,sev,status,seen,action);root.appendChild(tr);
    }
  }
  function sensors(d){
    const root=$('sensor-list');root.replaceChildren();
    const obs=d.sensors.input;
    const sensorInfo=d.sensors.platform==='darwin' ?
      (obs?.state==='ok'?[`Metadata audit`,`${obs.keyboard_taps||0} observable keyboard-event tap(s)`,false]:['macOS tap audit',`State: ${obs?.state||'unavailable'}`,true]):
      ['Platform input audit',d.sensors.platform==='linux'?'Linux input-device monitoring':'Not available on this platform',true];
    const items=[
      ['Process monitoring',d.sensors.process?'Scan records available':'Waiting for first scan',!d.sensors.process],
      ['Persistence monitoring',d.sensors.persistence?'Startup metadata monitored':'Waiting for first scan',!d.sensors.persistence],
      sensorInfo,
      ['Detection rules',String(d.sensors.rule_count)+' configured rules',false],
    ];
    for(const [title,subtitle,warn] of items){
      const row=document.createElement('div');row.className='v2-sensor-item';
      const l=document.createElement('div');const t=document.createElement('strong');t.textContent=title;const sub=document.createElement('small');sub.textContent=subtitle;l.append(t,sub);
      const status=document.createElement('span');status.className='v2-pill-status'+(warn?' warn':'');status.textContent=warn?'Check':'Available';row.append(l,status);root.appendChild(row);
    }
  }
  function paint(d){
    const specs=[['k-total',d.stats.total,'spark-total',d.series.Total,palette.Total],
      ['k-high',d.stats.high,'spark-high',d.series.High,palette.High],
      ['k-medium',d.stats.medium,'spark-medium',d.series.Medium,palette.Medium],
      ['k-open',d.stats.open,'spark-open',d.series.Open,palette.Open],
      ['k-tap',d.stats.input_taps,'spark-tap',d.series.InputTap,palette.InputTap],
      ['k-persist',d.stats.persistence,'spark-persist',d.series.Persistence,palette.Persistence],
      ['k-scans',d.stats.scans,'spark-scans',d.series.Scans,palette.Scans],
      ['k-visibility',d.stats.visibility===null?'—':d.stats.visibility+'%','spark-visibility',Array(d.buckets.length).fill(d.stats.visibility||0),palette.Visibility]];
    for(const [id,n,chart,values,color] of specs){$(id).textContent=String(n);spark(chart,values,color);}
    severityChart(d);timelineChart(d);ruleChart(d);recent(d);sensors(d);
    $('data-status').textContent='Updated '+fmtTime(d.generated_at);
    $('header-refresh').textContent='Last refresh: '+fmtTime(d.generated_at);
  }
  async function load(){
    if(busy)return;busy=true;$('data-status').textContent='Refreshing…';
    try{
      const params=new URLSearchParams({range:$('range').value});
      if(selectedDevice)params.set('device_id',selectedDevice);
      const response=await fetch('/api/dashboard/analytics?'+params.toString(),{credentials:'same-origin',cache:'no-store'});
      if(response.status===401){window.location.assign('/login');return;}
      if(!response.ok)throw Error('HTTP '+response.status);
      paint(await response.json());
    }catch(err){$('data-status').textContent='Dashboard unavailable · '+err.message;}
    finally{busy=false;}
  }
  async function loadDevices(){
    const response=await fetch('/api/devices',{credentials:'same-origin',cache:'no-store'});
    if(!response.ok)throw Error('HTTP '+response.status);
    const select=$('device');
    for(const device of (await response.json()).devices){
      const option=document.createElement('option');
      option.value=device.device_id;
      option.textContent=device.name+' ('+device.platform+')';
      select.appendChild(option);
    }
  }
  $('range').addEventListener('change',load);
  $('device').addEventListener('change',event=>{selectedDevice=event.target.value;load();});
  $('refresh-data').addEventListener('click',load);
  loadDevices().then(load).catch(err=>{$('data-status').textContent='Device list unavailable · '+err.message;load();});
  setInterval(()=>{if(!document.hidden)load()},30000);
})();
