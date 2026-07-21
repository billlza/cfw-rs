(()=>{var D={product:{name:"Clash for Mac",version:"0.3.1",parity_source:"Clash for Windows 0.20.39 macOS arm64 public release artifact"},pages:[{id:"general",title:"General",summary:"Overview, runtime status, mode, system proxy and TUN toggles."},{id:"proxies",title:"Proxies",summary:"Proxy groups, selections, delay indicators and quick switching."},{id:"profiles",title:"Profiles",summary:"Subscription import, update, validation and profile lifecycle."},{id:"providers",title:"Providers",summary:"Proxy providers, rule providers, health checks and update actions."},{id:"logs",title:"Logs",summary:"Core logs, helper logs and filtered runtime diagnostics."},{id:"connections",title:"Connections",summary:"Live connection list, close-all action and traffic visibility."},{id:"rules",title:"Rules",summary:"Rule matching visibility and router/provider diagnostics."},{id:"settings",title:"Settings",summary:"Shell settings, startup, deep link, helper and migration options."},{id:"feedback",title:"Feedback",summary:"About, feedback and migration references from the original app."}],settings:{launch_at_login:!1,random_controller_port:!0,retain_window_bounds:!0,show_tray_proxy_delay_indicator:!0,check_for_updates:!1,only_arm64_macos_supported:!0},platform:{minimum_macos:"13.0",intel_supported:!1,system_proxy_strategy:"objc2 SystemConfiguration SCPreferences with networksetup fallback",helper_strategy:"SMAppService privileged helper (Login Items approval required)",launchd_strategy:"typed launchd contract, no ad-hoc shell scripts in product logic",tun_strategy:"SmAppServiceRootHelper"},quality:{performance:{multiplier_vs_cfw_02039:3,cold_start_p95_ms:700,page_switch_p95_ms:16,proxy_toggle_p95_ms:150,profile_apply_p95_ms:450,max_idle_rss_mb:90,log_ingest_events_per_sec:1e4},stability:{crash_free_session_rate_basis_points:9995,restore_system_proxy_on_exit:!0,rollback_failed_profile_apply:!0,idempotent_helper_install:!0,tun_failure_restores_previous_route:!0,single_instance_deep_link_safe:!0},parity_gates:[]}},m={persisted:!1,paths:{app_home:"~/Library/Application Support/Clash for Mac",settings_file:"~/Library/Application Support/Clash for Mac/cfw-settings.yaml",config_file:"~/Library/Application Support/Clash for Mac/config.yaml",profiles_dir:"~/Library/Application Support/Clash for Mac/profiles",logs_dir:"~/Library/Application Support/Clash for Mac/logs",cores_dir:"~/Library/Application Support/Clash for Mac/cores",helpers_dir:"~/Library/Application Support/Clash for Mac/helpers"},settings:{schema_version:1,runtime_mode:"Rule",active_profile:null,system_proxy:!1,proxy_bypass:[],tun_mode:!1,mixin:!1,mixin_yaml:"",profile_parser_script:"",tray_script:"",child_process_command:"",allow_lan:!1,enable_ipv6:!1,launch_at_login:!1,silent_start:!1,break_connections_on_proxy_change:!0,theme:"light",font_family:"","interface-name":"",mixed_port:7890,external_controller_host:"127.0.0.1",external_controller_port:9090,secret:null,retain_window_bounds:!0,show_tray_proxy_delay_indicator:!0,usePacScript:!1,pacScript:"",randomMixedPort:!1,delayTestUrl:"http://www.gstatic.com/generate_204",coreKind:"clash_rs",core_kind:"clash_rs",only_arm64_macos_supported:!0}},R={state:"MissingBinary",pid:null,message:"Missing ~/Library/Application Support/Clash for Mac/cores/clash-rs",spec:{binary_path:"~/Library/Application Support/Clash for Mac/cores/clash-rs",config_path:"~/Library/Application Support/Clash for Mac/config.yaml",home_dir:"~/Library/Application Support/Clash for Mac",log_file:"~/Library/Application Support/Clash for Mac/logs/clash-core.log",controller_host:"127.0.0.1",controller_port:9090,mixed_port:7890,core_kind:"clash_rs"}},s={payload:D,settingsSnapshot:m,coreStatus:R,networkDiagnostics:null,activePage:"general",mode:"Rule",logLevel:"info",proxyFilter:"",activeProxyGroup:null,collapsedProxyGroups:new Set,logFilter:"all",logSearch:"",logsPaused:!1,connectionSearch:"",ruleSearch:"",mixinYaml:"",pacScript:"",profileParserScript:"",trayScript:"",childProcessCommand:"",connectionSort:"age",connectionSortDesc:!1,connectionPaused:!1,connectionDetailId:null,closingConnectionIds:new Set,closingAllConnections:!1,deepLinks:[],lastRefresh:"Just now",controllerStatus:"reference preview only",toggles:{systemProxy:!1,tunMode:!1,mixin:!1,allowLan:!1,startAtLogin:!1,breakOnProxyChange:!0,silentStart:!1,testingDelays:!1,hideUnavailable:!1,enableIpv6:!1,proxyDelayIndicator:!0,showProxyFilter:!0,showProxiesList:!0,usePacScript:!1,showProcess:!0},proxyBlinkNode:null,traffic:{upload:0,download:0,runtimeSeconds:0,memoryMb:0},coreStartedAt:null,serviceModeStatus:null,geoipStatus:null,geoipUpdating:!1,controllerVersion:null,connectionStream:{at:0,uploadTotal:0,downloadTotal:0,rows:new Map},profiles:[],profileInspector:null,profileContextMenu:null,glassDialog:null,proxyGroups:[],logs:[],connections:[],providers:[],ruleProviders:[],rules:[],providerActions:new Set,providerBulkActions:new Set};var we=new Set(["general","proxies","profiles","providers","logs","connections","rules","settings","feedback"]),se=200,_e=500,w={renderFrame:null,connectionsPatchFrame:null,globalEventsBound:!1,connectionRowEls:null,delayTestGeneration:0};var U=()=>window.__TAURI__,xe=e=>new Promise(t=>window.setTimeout(t,e)),p=async(e,t={})=>{let a=U();if(!a?.core?.invoke){if(e==="boot_payload")return D;if(e==="quit_app"||e==="force_quit_app")return null;if(e==="current_platform_design")return D.platform;if(e==="provision_core_binary")return{installed:!1,source_path:null,target_path:R.spec.binary_path,message:"Bundled core provisioning is unavailable outside Tauri"};if(e==="install_core_from_url"||e==="install_latest_mihomo_core"||e==="install_pinned_mihomo_core")throw new Error("Core installer is unavailable outside the Tauri runtime");if(e==="system_proxy_state")return s.toggles.systemProxy?"Enabled":"Disabled";if(e==="network_diagnostics")return null;if(e==="read_settings_snapshot")return m;if(e==="write_settings_snapshot")return{...m,persisted:!0,settings:t.settings};if(e==="reset_settings_snapshot")return m;if(e==="set_system_proxy_enabled")return{...m,persisted:!0,settings:{...m.settings,system_proxy:t.enabled}};if(e==="set_tun_enabled"){if(t.enabled)throw new Error("TUN runtime is unavailable in browser preview");return{...m,persisted:!0,settings:{...m.settings,tun_mode:t.enabled}}}if(e==="run_tray_script")return{status:0,stdout:"preview tray script",stderr:""};if(e==="run_child_process")return{status:0,stdout:"preview child process",stderr:""};if(e==="toggle_devtools"||e==="move_dashboard_to_nearest_monitor")return null;if(e==="set_mixin_enabled")return{...m,persisted:!0,settings:{...m.settings,mixin:t.enabled}};if(e==="set_launch_at_login_enabled")return{...m,persisted:!0,settings:{...m.settings,launch_at_login:t.enabled}};if(e==="install_helper_service")return{...m,persisted:!0,settings:{...m.settings,service_mode:"installed"}};if(e==="uninstall_helper_service")return{...m,persisted:!0,settings:{...m.settings,service_mode:"not-installed"}};if(e==="controller_snapshot"||e==="providers_snapshot"||e==="rules_snapshot"||e==="update_proxy_provider"||e==="update_rule_provider"||e==="health_check_proxy_provider")return null;if(e==="update_all_proxy_providers")return O("update-proxy");if(e==="update_all_rule_providers")return O("update-rule");if(e==="health_check_all_proxy_providers")return O("health-check-proxy");if(e==="service_mode_status")return"Unknown";if(e==="controller_version")return{version:"preview",meta:!0};if(e==="read_runtime_config_text")return`mixed-port: 7890
`;if(e==="dns_query")return{Status:0,Answer:[]};if(e==="set_bind_address")return{...m,persisted:!0,settings:{...m.settings,"bind-address":t.address}};if(e==="open_login_items_settings")return null;if(e==="apply_restore_dns_servers")return"updated DNS on 0/0 service(s)";if(e==="check_for_updates")return{available:!1,current:"0.2.0"};if(e==="install_available_update")return{installed:!1,reason:"preview"};if(e==="disable_service_mode")return null;if(e==="enable_service_mode")return"RequiresApproval";if(e==="disable_service_mode")return null;if(e==="geoip_database_status")return{present:!1,file_name:"geoip.metadb",path:`${m.paths.app_home}/geoip.metadb`,mtime_ms:null,size_bytes:null};if(e==="update_geoip_database"){let o=Date.now();return{status:{present:!0,file_name:"geoip.metadb",path:`${m.paths.app_home}/geoip.metadb`,mtime_ms:o,size_bytes:1024},source_url:"https://example.invalid/geoip.metadb",bytes:1024}}if(e==="refresh_tray_menu"||e==="start_connections_stream"||e==="start_log_stream")return null;if(e==="parse_deep_links")return(t.urls??[]).map(o=>({raw:o,intent:null,error:"parse_deep_links is unavailable outside Tauri"}));if(e==="import_profile_url"){let o=`import-${Date.now()}`;return{id:o,name:t.name??"Imported Profile",path:`${m.paths.profiles_dir}/${o}.yaml`,bytes:0,activated:t.activate}}if(e==="import_profile_text"){let o=`local-${Date.now()}`;return{id:o,name:t.name??"Local Profile",path:`${m.paths.profiles_dir}/${o}.yaml`,bytes:t.body?.length??0,activated:t.activate}}if(e==="update_profile")throw new Error("Profile update is unavailable outside the Tauri runtime");if(e==="read_profile_text")return{id:t.id,name:t.id,path:`${m.paths.profiles_dir}/${t.id}.yaml`,body:`proxies: []
proxy-groups: []
rules: []
`,generated_body:`mixed-port: 7890
proxies: []
proxy-groups: []
rules: []
`,active:!1,source_url:null};if(e==="save_profile_text")return{id:t.id,path:"",bytes:t.body?.length??0,active:!1};if(e==="profile_qrcode_svg")throw new Error("Profile QRCode is unavailable outside the Tauri runtime");if(e==="profiles_snapshot")return[];if(e==="delete_profile")return!0;if(e==="reveal_profile"||e==="open_profile_externally"||e==="open_external_url"||e==="update_profile_info"||e==="reveal_home_directory"||e==="reveal_logs_directory")return null;if(e==="apply_active_profile")throw new Error("Profile apply is unavailable outside the Tauri runtime");return e==="reapply_runtime_config"?"/tmp/config.yaml":e==="set_proxy_mode"?null:e==="set_allow_lan"?{...m,persisted:!0,settings:{...m.settings,allow_lan:t.enabled}}:e==="set_ipv6"?{...m,persisted:!0,settings:{...m.settings,enable_ipv6:t.enabled}}:e==="set_log_level"||e==="select_proxy"?null:e==="test_proxy_delays"?[]:e==="close_connection"||e==="close_all_connections"||e==="flush_fake_ip_cache"?null:e==="core_status"?R:e==="start_core"?R:e==="stop_core"?{...R,state:"Stopped",message:"Core stopped"}:null}return a.core.invoke(e,t)},E=async(e,t)=>{let a=U();return a?.event?.listen?a.event.listen(e,t):()=>{}};function d(e){return String(e).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;")}function Se(e){let t=Math.max(0,Math.floor(Number(e)||0)),a=Math.floor(t/3600).toString().padStart(2,"0"),o=Math.floor(t%3600/60).toString().padStart(2,"0"),r=Math.floor(t%60).toString().padStart(2,"0");return`${a} : ${o} : ${r}`}function Q(e){switch(e){case"Enabled":return"Enabled";case"RequiresApproval":return"Needs Approval";case"NotRegistered":case"NotFound":return"Not Installed";default:return"Unknown"}}function $e(e){return e!=="Enabled"}function ke(e,t){return e?"On":t==="Enabled"?"Off":"Service Mode required"}function Ce(e,t){if(t)return"Updating\u2026";if(!e)return"Loading\u2026";if(!e.present)return"Missing";if(e.mtime_ms==null)return e.file_name||"Present";let a=new Date(e.mtime_ms);if(Number.isNaN(a.getTime()))return e.file_name||"Present";let o=r=>String(r).padStart(2,"0");return`${a.getFullYear()}-${o(a.getMonth()+1)}-${o(a.getDate())} ${o(a.getHours())}:${o(a.getMinutes())}`}function x(e){if(!Number.isFinite(e)||e<=0)return"0 B";let t=["B","KB","MB","GB"],a=e,o=0;for(;a>=1024&&o<t.length-1;)a/=1024,o+=1;return`${a>=10||o===0?a.toFixed(0):a.toFixed(1)} ${t[o]}`}function fe(e){let t=e*1024;return t<1024?`${t.toFixed(t<10?2:0)} KB/s`:`${e.toFixed(1)} MB/s`}function O(e){return{action:e,requested:0,succeeded:[],failed:[]}}function G(e,t){return`${e}:${t}`}function oe(e,t){let a=Number(t?.requested??0),o=t?.succeeded?.length??0,r=t?.failed?.length??0,n=(t?.failed??[]).slice(0,3).map(c=>`${c.name}: ${c.error}`).join("; ");return`${e}: ${o}/${a} succeeded${r?`, ${r} failed${n?` (${n})`:""}`:""}`}function re(e){return(e?.failed?.length??0)===0}function Pe(e=[]){let t=e.at(-1);return Number.isFinite(t?.delay)?t.delay:null}function he(e){let t=String(e??"info").toLowerCase();return["warn","wrn","warning"].includes(t)?"warning":["err","error","fatal","ftl"].includes(t)?"error":["debug","dbg","trace","trc"].includes(t)?"debug":"info"}function ne(e){if(!e)return null;try{return new RegExp(e,"i")}catch{return null}}function me(e){return s.payload.pages.find(t=>t.id===e)??s.payload.pages[0]}function k(){return s.profiles.find(e=>e.active)??s.profiles[0]??{id:"none",name:"No Profile",type:"Local",updated:"never",rules:0,traffic:"0 B",active:!1}}function v(e){if(!e?.settings)return;s.settingsSnapshot=e;let t=e.settings;s.mode=t.runtime_mode??s.mode,s.logLevel=t.logLevel??t["log-level"]??s.logLevel,s.toggles.systemProxy=!!t.system_proxy,s.toggles.tunMode=!!t.tun_mode,s.toggles.mixin=!!t.mixin,s.mixinYaml=t.mixin_yaml??t.mixinYaml??"",s.profileParserScript=t.profile_parser_script??t.profileParserScript??"",s.trayScript=t.tray_script??t.trayScript??"",s.childProcessCommand=t.child_process_command??t.childProcessCommand??"",s.toggles.allowLan=!!t.allow_lan,s.toggles.enableIpv6=!!t.enable_ipv6,s.toggles.startAtLogin=!!t.launch_at_login,s.toggles.silentStart=!!t.silent_start,s.toggles.breakOnProxyChange=!!t.break_connections_on_proxy_change,s.toggles.proxyDelayIndicator=!!t.show_tray_proxy_delay_indicator,s.toggles.usePacScript=!!(t.usePacScript??t.use_pac_script),s.pacScript=t.pacScript??t.pac_script??s.pacScript??"",Ve(t)}function S(){let e=s.settingsSnapshot?.settings??m.settings;return{...e,runtime_mode:s.mode,logLevel:s.logLevel,system_proxy:s.toggles.systemProxy,proxy_bypass:(document.querySelector("[data-proxy-bypass]")?.value??(s.settingsSnapshot?.settings?.proxy_bypass??[]).join(`
`)).split(/[\n,]+/).map(t=>t.trim()).filter(Boolean),tun_mode:s.toggles.tunMode,mixin:s.toggles.mixin,mixin_yaml:document.querySelector("[data-mixin-yaml]")?.value??s.mixinYaml??e.mixin_yaml??"",profile_parser_script:document.querySelector("[data-profile-parser-script]")?.value??s.profileParserScript??e.profile_parser_script??"",tray_script:document.querySelector("[data-tray-script]")?.value?.trim()??s.trayScript??e.tray_script??"",child_process_command:document.querySelector("[data-child-process-command]")?.value?.trim()??s.childProcessCommand??e.child_process_command??"",allow_lan:s.toggles.allowLan,enable_ipv6:s.toggles.enableIpv6,launch_at_login:s.toggles.startAtLogin,silent_start:s.toggles.silentStart,break_connections_on_proxy_change:s.toggles.breakOnProxyChange,show_tray_proxy_delay_indicator:s.toggles.proxyDelayIndicator,usePacScript:s.toggles.usePacScript,pacScript:document.querySelector("[data-pac-script]")?.value??s.pacScript??e.pacScript??e.pac_script??"",theme:document.querySelector("[data-theme-setting]")?.value??e.theme??"light",font_family:document.querySelector("[data-font-family]")?.value?.trim()??e.font_family??"","interface-name":document.querySelector("[data-outbound-interface]")?.value?.trim()??e["interface-name"]??e.interfaceName??"",randomMixedPort:document.querySelector("[data-random-mixed-port]")?.checked??!!(e.randomMixedPort??e.random_mixed_port),delayTestUrl:document.querySelector("[data-delay-test-url]")?.value?.trim()||e.delayTestUrl||e.delay_test_url||"http://www.gstatic.com/generate_204",coreKind:document.querySelector("[data-core-kind]")?.value||e.coreKind||e.core_kind||"clash_rs",core_kind:document.querySelector("[data-core-kind]")?.value||e.coreKind||e.core_kind||"clash_rs"}}function Ve(e){let t=e.theme==="dark"?"dark":"light";document.documentElement.dataset.theme=t;let a=String(e.font_family??e.fontFamily??"").trim();document.documentElement.style.setProperty("--sans",a?`"${a}", "Avenir Next", "SF Pro Text", "Helvetica Neue", sans-serif`:'"Avenir Next", "SF Pro Text", "Helvetica Neue", sans-serif')}function We(e){if(!e)return;let t=e.config??{},a=t.mode?t.mode[0].toUpperCase()+t.mode.slice(1).toLowerCase():null;["Global","Rule","Direct","Script"].includes(a)&&(s.mode=a);let o=t["allow-lan"]??t.allow_lan,r=t["mixed-port"]??t.mixed_port;typeof o=="boolean"&&(s.toggles.allowLan=o),typeof t.ipv6=="boolean"&&(s.toggles.enableIpv6=t.ipv6),(t["log-level"]||t.log_level)&&(s.logLevel=t["log-level"]??t.log_level),typeof r=="number"&&(s.settingsSnapshot.settings.mixed_port=r);let n=new Map((e.proxies?.proxies??[]).map(u=>[u.name,u])),c=e.proxies?.groups??[],l=new Map(c.map(u=>[u.name,u]));c.length&&(s.proxyGroups=c.map(u=>({name:u.name,type:u.kind,now:u.now??u.options?.[0]??"DIRECT",options:(u.options??[]).map(f=>{let b=n.get(f),h=l.get(f);return{name:f,delay:Pe(b?.history??h?.history??[]),dead:!1,kind:b?.kind??b?.type??h?.kind??u.kind??"Proxy",udp:b?.udp??null}})}))),Ee(e.connections),s.controllerStatus="controller live"}function Ee(e){if(!e)return;let t=Date.now(),a=s.connectionStream.at?Math.max(.25,(t-s.connectionStream.at)/1e3):0,o=e.upload??e.uploadTotal??e.upload_total??0,r=e.download??e.downloadTotal??e.download_total??0,n=s.connectionStream.rows??new Map,c=e.connections??[];s.connections=c.map(l=>{let u=l.metadata??{},f=u.host||u.destinationIP||u.destination_ip||"unknown",b=l.rulePayload??l.rule_payload,h=[l.rule,b].filter(Boolean).join(","),P=n.get(l.id),C=l.upload??0,q=l.download??0,B=P&&a?Math.max(0,(C-P.upload)/a):0,T=P&&a?Math.max(0,(q-P.download)/a):0;return{id:l.id,host:f,rule:h||"MATCH",chains:l.chains??[],upload:x(C),download:x(q),uploadBytes:C,downloadBytes:q,uploadSpeedBytes:B,downloadSpeedBytes:T,speed:`${x(B)}/s up \xB7 ${x(T)}/s down`,age:l.start?l.start.slice(11,19):"live",start:l.start,metadata:u}}),a&&(s.traffic.upload=Math.max(0,(o-s.connectionStream.uploadTotal)/a/1024/1024),s.traffic.download=Math.max(0,(r-s.connectionStream.downloadTotal)/a/1024/1024)),s.connectionStream={at:t,uploadTotal:o,downloadTotal:r,rows:new Map(c.map(l=>[l.id,{upload:l.upload,download:l.download}]))},s.controllerStatus="controller live stream"}function Ye(e){if(!e)return!1;let t=e.proxy_providers??[],a=e.rule_providers??[];return s.providers=t.map(o=>({name:o.name,type:o.kind,vehicle:o.vehicle_type,updated:o.updated_at??"unknown",health:o.extra?.healthCheck?.lastResult??o.extra?.healthcheck?.lastResult??"Unknown",proxies:o.proxies?.length??0})),s.ruleProviders=a.map(o=>({name:o.name,type:o.kind,behavior:o.behavior??o.vehicle_type,updated:o.updated_at??"unknown",rules:o.rules?.length??0})),!0}function Ke(){let e=ne(s.logSearch);return s.logs.filter(t=>{let a=s.logFilter==="all"||t.level===s.logFilter,o=[t.time,t.level,t.source,t.message,...(t.fields??[]).map(n=>`${n.key}=${n.value}`)].join(" "),r=!s.logSearch||(e?e.test(o):o.toLowerCase().includes(s.logSearch.toLowerCase()));return a&&r}).slice(0,se)}function Te(){let e=ne(s.connectionSearch),t=s.connections.filter(r=>{let n=r.metadata??{},c=[r.host,r.rule,...r.chains??[],n.processPath,n.process_path,n.sourceIP,n.source_ip,n.destinationIP,n.destination_ip,n.network,n.type].filter(Boolean).join(" ");return!s.connectionSearch||(e?e.test(c):c.toLowerCase().includes(s.connectionSearch.toLowerCase()))}),a={host:r=>r.host,speed:r=>r.uploadSpeedBytes+r.downloadSpeedBytes,upload:r=>r.uploadBytes,download:r=>r.downloadBytes,age:r=>Date.parse(r.start||"")||0},o=a[s.connectionSort]??a.age;return[...t].sort((r,n)=>{let c=o(r),l=o(n),u=typeof c=="string"?c.localeCompare(String(l)):c-l;return s.connectionSortDesc?-u:u}).slice(0,_e)}function Qe(){let e=ne(s.ruleSearch);return s.rules.filter(t=>{let a=[t.index,t.type,t.payload,t.proxy,t.hits].filter(Boolean).join(" ");return!s.ruleSearch||(e?e.test(a):a.toLowerCase().includes(s.ruleSearch.toLowerCase()))}).slice(0,2e3)}function Xe(){let e=document.getElementById("nav");e.innerHTML=s.payload.pages.filter(t=>we.has(t.id)).map((t,a)=>`
        <button class="nav-item${t.id===s.activePage?" active":""}" data-page="${d(t.id)}">
          <span>${a+1}</span>
          <b>${d(t.title)}</b>
        </button>
      `).join("")}function M(e,t,a,o={}){let r=s.toggles[e]?"checked":"",n=o.disabled?"disabled":"";return`
    <label class="toggle-row ${o.disabled?"disabled":""}">
      <span>
        <b>${d(t)}</b>
        <small>${d(a)}</small>
      </span>
      <input type="checkbox" data-toggle="${d(e)}" ${r} ${n} />
      <i></i>
    </label>
  `}function j(e,t,a={}){let o=s.toggles[e]?"checked":"",r=a.disabled?"disabled":"";return`
    <label class="inline-switch ${a.disabled?"disabled":""}">
      <span class="visually-hidden">${d(t)}</span>
      <input type="checkbox" data-toggle="${d(e)}" ${o} ${r} />
      <i></i>
    </label>
  `}function Je(){return`
    <svg class="cfw-cat-logo" viewBox="0 0 112 96" aria-hidden="true">
      <path d="M23 86c-12 0-19-8-19-17 0-9 7-15 16-15 4 0 7 1 10 3l4-43 17 16 12-1 18-17 6 72c-17 2-40 2-64 2Z" />
      <path class="cat-tail" d="M22 70c-14 4-24-4-20-15 2-6 8-9 13-7" />
      <circle cx="43" cy="45" r="4" />
      <circle cx="71" cy="45" r="4" />
      <path class="cat-mouth" d="M54 58c3 3 6 3 9 0" />
    </svg>
  `}function De(e){let t='width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"';switch(e){case"terminal":return`<svg ${t}><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm1 3v2l3 2-3 2v2l5-3.5L5 7zm7 8h6v2h-6v-2z"/></svg>`;case"sync":return`<svg ${t}><path d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46A7.93 7.93 0 0 0 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74A7.93 7.93 0 0 0 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z"/></svg>`;case"sync-off":return`<svg ${t}><path d="M20 12c0-4.42-3.58-8-8-8V1L8 5l1.7 1.7C12.9 6.8 15.2 8.9 16.1 11.5l1.7 1.7c.13-.4.2-.8.2-1.2zM4.27 3 3 4.27l2.05 2.05A7.95 7.95 0 0 0 4 12c0 4.42 3.58 8 8 8v3l4-4-1.3-1.3L19.73 21 21 19.73 4.27 3zM12 18c-3.31 0-6-2.69-6-6 0-1.3.41-2.5 1.11-3.48L14.48 16.9A5.9 5.9 0 0 1 12 18z"/></svg>`;case"info":return`<svg ${t}><path d="M12 2a10 10 0 1 0 .001 20.001A10 10 0 0 0 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>`;case"device-hub":return`<svg ${t}><path d="M17 16h-2v-2h2v2zm-4 0h-2v-2h2v2zm-4 0H7v-2h2v2zm10-6h-2V8h2v2zm-4 0h-2V8h2v2zm-4 0H7V8h2v2zm10-6H5c-1.1 0-2 .9-2 2v14h18V6c0-1.1-.9-2-2-2zm0 14H5V6h14v10z"/></svg>`;case"memory":return`<svg ${t}><path d="M15 9H9v6h6V9zm-2 4h-2v-2h2v2zm8-2V9h-2V7c0-1.1-.9-2-2-2h-2V3h-2v2h-2V3H9v2H7c-1.1 0-2 .9-2 2v2H3v2h2v2H3v2h2v2c0 1.1.9 2 2 2h2v2h2v-2h2v2h2v-2h2c1.1 0 2-.9 2-2v-2h2v-2h-2v-2h2zm-4 6H7V7h10v10z"/></svg>`;case"dns":return`<svg ${t}><path d="M20 13H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1v-6c0-.55-.45-1-1-1zM7 19c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM20 3H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1zM7 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>`;case"play":return`<svg ${t}><path d="M8 5v14l11-7L8 5z"/></svg>`;case"public":return`<svg ${t}><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>`;case"settings":return`<svg ${t}><path d="M19.14 12.94c.04-.31.06-.63.06-.94s-.02-.63-.06-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.49.49 0 0 0-.59-.22l-2.39.96a7.2 7.2 0 0 0-1.62-.94l-.36-2.54A.48.48 0 0 0 14 2h-4a.48.48 0 0 0-.48.42l-.36 2.54c-.59.24-1.13.56-1.62.94l-2.39-.96a.49.49 0 0 0-.59.22L2.65 8.87a.49.49 0 0 0 .12.61l2.03 1.58c-.04.31-.06.63-.06.94s.02.63.06.94L2.77 14.52a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.42.48.42h4c.24 0 .44-.18.48-.42l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32a.49.49 0 0 0-.12-.61l-2.01-1.58zM12 15.5A3.5 3.5 0 1 1 12 8.5a3.5 3.5 0 0 1 0 7z"/></svg>`;case"history":return`<svg ${t}><path d="M13 3a9 9 0 0 0-9 9H1l3.89 3.89.07.14L9 12H6a7 7 0 0 1 7-7 7 7 0 0 1 7 7 7 7 0 0 1-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42A8.95 8.95 0 0 0 13 21a9 9 0 0 0 0-18zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/></svg>`;default:return""}}function A(e,t,a,o={}){let r=o.tone?` ${o.tone}`:"",n=o.active?" active":"";return`<button type="button" class="general-icon${r}${n}" data-action="${d(e)}" title="${d(a)}">${De(t)}</button>`}function Re(e){let t=e["bind-address"]??e.bindAddress??(s.toggles.allowLan?"*":"127.0.0.1");return String(t)}function Ze(e){return e==="Enabled"?"ok":$e(e)?"warn":"muted"}function Ie(){let e=s.settingsSnapshot?.settings??m.settings,a=(s.payload.product??D.product).version??"0.3.1",o=s.coreStatus??R,r=o.state==="Running",n=e.external_controller_host??"127.0.0.1",c=e.external_controller_port??9090,l=`${n}:${c}`,u=s.controllerVersion?.version??(r?"Connected":o.state),f=r?"cfw-status-dot on":"cfw-status-dot",b=s.logLevel??e.logLevel??e["log-level"]??"info",h=Q(s.serviceModeStatus),P=s.serviceModeStatus==="Enabled",C=!!(e.randomMixedPort??e.random_mixed_port),q=Re(e),B=Ze(s.serviceModeStatus);return`
    <div class="cfw-general-view">
      <section class="cfw-header">
        <div class="cfw-app-mark">${Je()}</div>
        <div class="cfw-title">
          <span>Clash for Mac</span>
          <small>v${d(a)}</small>
        </div>
      </section>

      <section class="cfw-content">
        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Port</span>
            <span class="general-icons">
              ${A("copy-proxy-exports","terminal","Copy proxy export commands for Terminal")}
              ${A("toggle-random-mixed-port",C?"sync":"sync-off","random mixed port",{active:C})}
            </span>
          </div>
          <div class="cfw-row-right">
            <input class="cfw-number" data-mixed-port type="number" min="1" max="65535" value="${e.mixed_port}" aria-label="mixed-port" ${C?"disabled":""}>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Allow LAN</span>
            <span class="general-icons">
              ${A("allow-lan-info","info","Turn on to listen on all interfaces by default, or else only listen on 127.0.0.1. Change Bind Address to pick an interface.")}
              ${A("show-network-interfaces","device-hub","network interfaces")}
            </span>
          </div>
          <div class="cfw-row-right">
            <button type="button" class="cfw-text-button" data-action="edit-bind-address" title="Edit bind address">Bind: ${d(q)}</button>
            ${j("allowLan","Allow LAN")}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Log Level</div>
          <div class="cfw-row-right">
            <select class="cfw-select" data-log-level>
              ${["info","warning","error","debug","trace","silent"].map(T=>`
                <option value="${T}" ${b===T?"selected":""}>${T}</option>
              `).join("")}
            </select>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">IPv6</div>
          <div class="cfw-row-right">${j("enableIpv6","IPv6")}</div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Clash Core</span>
            <span class="general-icons">
              ${A("preview-runtime-config","memory","Preview the final configuration file that was submitted to Clash Core")}
              ${A("dns-query","dns","Resolve a host using Clash core")}
              ${A("script-test","play","Test script using by Script mode")}
            </span>
          </div>
          <div class="cfw-row-right">
            <button type="button" class="cfw-text-button core-version-link" data-action="open-controller-dashboard" title="Open controller dashboard">
              <i class="${f}"></i>
              <span>${d(u)}${r?` (${d(String(c))})`:""}</span>
            </button>
            <button type="button" class="general-icon" data-action="${o.state==="MissingBinary"?"install-pinned-core":r?"stop-core":"start-core"}" title="${r?"Stop core":o.state==="MissingBinary"?"Install pinned mihomo core":"Start core"}">${r?"\u25A0":"\u25B6"}</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Home Directory</div>
          <div class="cfw-row-right">
            <button class="cfw-text-button" data-action="open-home-directory">Open Folder</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">GeoIP Database</div>
          <div class="cfw-row-right">
            <button class="cfw-text-button" data-action="update-geoip-database" title="${s.geoipStatus?.path?d(s.geoipStatus.path):"Download / refresh GeoIP database"}">${d(Ce(s.geoipStatus,s.geoipUpdating))}</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Service Mode</span>
            <span class="general-icons">
              <span class="general-icon ${B}" title="Service Mode status">${De("public")}</span>
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${h}</span>
            <button class="cfw-text-button" data-action="manage-service-mode">Manage</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>TUN Mode</span>
            <span class="general-icons">
              ${A("tun-info","info","To enable this mode, please install Service Mode first!")}
              ${A("tun-settings","settings","Settings")}
              ${A("tun-reset-dns","history","System DNS servers that will be set after TUN Mode is disabled")}
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${ke(s.toggles.tunMode,s.serviceModeStatus)}</span>
            ${j("tunMode","TUN Mode",{disabled:!P})}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Mixin</span>
            <span class="general-icons">
              ${A("mixin-info","info","Mixin merges YAML into the generated config before reload. Docs: profile mixin in Settings.")}
              ${A("edit-mixin","settings","Edit Mixin content")}
            </span>
          </div>
          <div class="cfw-row-right">${j("mixin","Mixin")}</div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">System Proxy</div>
          <div class="cfw-row-right">${j("systemProxy","System Proxy")}</div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Start with macOS</div>
          <div class="cfw-row-right">${j("startAtLogin","Start with macOS")}</div>
        </div>
      </section>
    </div>
  `}function qe(e){return e==null?"pending":e<=0?"dead":e<80?"fast":e<180?"mid":"slow"}function Be(e){return e==null?"Pending":e<=0?"Timeout":`${e} ms`}function Me(){if(typeof document<"u"&&document.hidden)return 2;let e=Number(navigator.hardwareConcurrency)||8;return Math.max(4,Math.min(16,e))}function pe(){w.delayTestGeneration=(w.delayTestGeneration??0)+1,s.toggles.testingDelays=!1}function et(){let e=document.querySelector("[data-proxy-node-grid]");if(!e)return[];let t=e.getBoundingClientRect(),a=[];return e.querySelectorAll("[data-proxy-node]").forEach(o=>{let r=o.getBoundingClientRect();if(r.bottom>=t.top&&r.top<=t.bottom){let n=o.getAttribute("data-proxy-node");n&&a.push(n)}}),a}function tt(e){let t=new Set(et()),a=[],o=[];for(let r of e)t.has(r)?a.push(r):o.push(r);return a.length?[...a,...o]:e}function ce(e,t){let a=typeof t=="number"&&Number.isFinite(t)?t:0;s.proxyGroups.forEach(o=>{o.options.forEach(r=>{r.name===e&&(r.delay=a,r.dead=a<=0)})})}function V(e){let t=e?new Set(e):null;document.querySelectorAll("[data-proxy-delay]").forEach(o=>{let r=o.getAttribute("data-proxy-delay");if(!r||t&&!t.has(r))return;let n=null;for(let c of s.proxyGroups){let l=c.options.find(u=>u.name===r);if(l){n=l.delay;break}}o.className=qe(n),o.textContent=Be(n)});let a=document.querySelector('[data-action="delay-test"]');a&&(a.classList.toggle("active",!!s.toggles.testingDelays),a.disabled=!!s.toggles.testingDelays)}function Le(e){e.forEach(t=>{let a=null;for(let o of s.proxyGroups){let r=o.options.find(n=>n.name===t);if(r){a=r;break}}a&&(a.delay===null||a.delay===void 0)&&ce(t,0)}),V(e)}function at(e){return String(e).replace(/[^a-z0-9_-]/gi,"-")}function X(e){return["selector","relay"].includes(String(e??"").toLowerCase())}function ie(e){let t='width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"';switch(e){case"scroll":return`<svg ${t} fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/><circle cx="18.5" cy="18.5" r="3.2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M20.8 20.8L23 23" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`;case"report":return`<svg ${t} fill="currentColor"><path d="M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3c-.72 0-1.3-.58-1.3-1.3s.58-1.3 1.3-1.3 1.3.58 1.3 1.3-.58 1.3-1.3 1.3zm1-4.3h-2V7h2v6z"/></svg>`;case"report-off":return`<svg ${t} fill="currentColor"><path d="M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3c-.72 0-1.3-.58-1.3-1.3s.58-1.3 1.3-1.3 1.3.58 1.3 1.3-.58 1.3-1.3 1.3zm1-4.3h-2V7h2v6z" opacity=".38"/></svg>`;case"delay":return`<svg ${t} fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12a10 10 0 0 1 20 0"/><path d="M5 12a7 7 0 0 1 14 0"/><path d="M8.5 12a3.5 3.5 0 0 1 7 0"/><path d="M12 12V7.5" stroke-width="2"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/></svg>`;case"eye":return`<svg ${t} fill="currentColor"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>`;case"eye-off":return`<svg ${t} fill="currentColor"><path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/></svg>`;default:return""}}function st(e){return e?e.dead?!0:typeof e.delay=="number"&&e.delay<=0:!1}function ot(){let e=s.proxyFilter.trim().toLowerCase(),t=s.proxyGroups.map(l=>({...l,options:l.options.filter(u=>{let f=!e||l.name.toLowerCase().includes(e)||u.name.toLowerCase().includes(e),b=s.toggles.hideUnavailable&&st(u)&&l.now!==u.name;return f&&!b})})).filter(l=>l.options.length||l.name.toLowerCase().includes(e)),a=t.find(l=>l.name===s.activeProxyGroup)??t.find(l=>X(l.type)&&/选择|select|proxy|节点/i.test(l.name))??t.find(l=>X(l.type)&&l.name.toUpperCase()!=="GLOBAL")??t.find(l=>X(l.type))??t[0]??null,o=a?X(a.type):!1,r=!!s.toggles.hideUnavailable,n=s.toggles.showProxiesList!==!1,c=s.proxyBlinkNode;return`
    <div class="proxy-layout">
      <div class="mode-switch proxy-mode-header" role="group" aria-label="Proxy mode">
        ${["Global","Rule","Direct","Script"].map(l=>`
          <button class="${s.mode===l?"selected":""}" data-mode="${l}">${l} <span>${rt(l)}</span></button>
        `).join("")}
      </div>

      <div class="cfw-proxy-page">
        ${a?`
          <div class="cfw-proxy-head">
            <div class="cfw-proxy-title">
              <span class="proxy-shield">\u25C7</span>
              <h2>${d(a.name)}</h2>
              <span class="proxy-type-badge">${d(a.type?.slice(0,1)??"S")}</span>
              <b>${d(a.now??"")}</b>
            </div>
            <div class="cfw-proxy-tools">
              <input class="proxy-filter" data-proxy-filter placeholder="Filter" value="${d(s.proxyFilter)}" aria-label="Filter proxies" />
              <button class="proxy-tool" data-action="scroll-to-selected-proxy" title="Scroll to selected proxy">${ie("scroll")}</button>
              <button class="proxy-tool ${r?"active":""}" data-action="toggle-hide-timed-out" title="Show/Hide timed-out proxies">${ie(r?"report-off":"report")}</button>
              <button class="proxy-tool ${s.toggles.testingDelays?"active":""}" data-action="delay-test" title="Test latency" ${s.toggles.testingDelays?"disabled":""}>${ie("delay")}</button>
              <button class="proxy-tool ${n?"active":""}" data-action="toggle-show-proxies" title="Show/hide proxies">${ie(n?"eye":"eye-off")}</button>
            </div>
          </div>
          <div class="cfw-proxy-content">
            ${n?`
            <div class="cfw-node-grid" data-proxy-node-grid>
              ${a.options.map(l=>`
                <button class="cfw-node-card ${a.now===l.name?"selected":""} ${c===l.name?"blink":""} ${o?"":"readonly"}" data-proxy-node="${d(l.name)}" ${o?`data-group="${d(a.name)}" data-node="${d(l.name)}"`:"disabled"} title="${o?"Select proxy":"This Clash group type is controlled by the core"}">
                  <i></i>
                  <span>
                    <strong>${nt(l.name)}${d(l.name)}</strong>
                    <small>${d(l.kind??"Proxy")} ${l.udp===!1?"":"<em>UDP</em>"}</small>
                  </span>
                  <b class="${qe(l.delay)}" data-proxy-delay="${d(l.name)}">${Be(l.delay)}</b>
                </button>
              `).join("")}
            </div>
            `:'<p class="empty proxy-list-hidden">Proxies hidden \u2014 click the eye to show this group\u2019s nodes.</p>'}
            <aside class="cfw-group-rail">
              ${t.map(l=>`
                <button class="${l.name===a.name?"active":""}" data-proxy-group-tab="${d(l.name)}" title="${d(l.name)}">${d(it(l.name))}</button>
              `).join("")}
            </aside>
          </div>
        `:'<p class="empty">Controller unavailable. No live proxy groups are being displayed.</p>'}
      </div>
    </div>
  `}function rt(e){return{Global:"\u2197",Rule:"\u219D",Direct:"\u2192",Script:"\u21AD"}[e]??""}function nt(e){let t=String(e??"");return/[\u{1F1E6}-\u{1F1FF}]/u.test(t)?"":/^(DIRECT|REJECT)$/i.test(t)?"\u2022 ":""}function it(e){let t=String(e??"").trim();if(!t)return"?";if(/^GLOBAL$/i.test(t))return"GLOBAL";let a=t.replace(/[\u{1F1E6}-\u{1F1FF}]/gu,"").replace(/[|｜丨&＆/\\()[\]{}【】「」『』·•._\-:：;；,，。!！?？"'“”‘’]+/g,"").replace(/\s+/g,"");return([...a].filter(r=>/[\u4e00-\u9fffA-Za-z0-9]/.test(r)).join("")||a||t).slice(0,6)}function lt(e){try{return new URL(e).host}catch{return e||"local file"}}function ct(e){return e.updateInterval?`interval ${e.updateInterval}`:e.sourceUrl?"remote":"local"}function Ue(e){if(!e||typeof e!="string")return null;let t=Object.create(null);for(let f of e.split(/[;\s]+/)){let b=f.indexOf("=");b<=0||(t[f.slice(0,b).trim().toLowerCase()]=f.slice(b+1).trim())}let a=Number(t.upload),o=Number(t.download),r=Number(t.total),n=Number(t.expire),c=(Number.isFinite(a)?a:0)+(Number.isFinite(o)?o:0),l=null;Number.isFinite(r)&&r>0&&(l=Math.max(0,Math.min(100,c/r*100)));let u=null;if(Number.isFinite(n)&&n>0){let f=new Date(n*1e3);if(!Number.isNaN(f.getTime())){let b=h=>String(h).padStart(2,"0");u=`${f.getFullYear()}-${b(f.getMonth()+1)}-${b(f.getDate())}`}}return{used:c,total:Number.isFinite(r)&&r>0?r:null,percent:l,expireDate:u}}function ve(e){if(!Number.isFinite(e)||e<0)return"0B";let t=["B","KB","MB","GB","TB"],a=e,o=0;for(;a>=1024&&o<t.length-1;)a/=1024,o+=1;return o===0?`${Math.round(a)}B`:`${a.toFixed(1)}${t[o]}`}function dt(e){if(!Number.isFinite(e)||e<=0)return"unknown";let t=Date.now()-e*1e3;if(t<0)return new Date(e*1e3).toLocaleString();let a=Math.floor(t/1e3);return a<45?"a few seconds":a<90?"1 minute":a<3600?`${Math.floor(a/60)} minutes`:a<5400?"1 hour":a<86400?`${Math.floor(a/3600)} hours`:new Date(e*1e3).toLocaleString()}function pt(e){let t=Ue(e.subscriptionUserinfo);if(t&&(t.total!=null||t.expireDate)){let a=[];return t.total!=null?(a.push(`<span>${d(ve(t.used))}</span>`),a.push(`<span>${d(ve(t.total))}</span>`)):a.push(`<span>${d(ve(t.used))}</span>`),t.expireDate&&a.push(`<span>${d(t.expireDate)}</span>`),a.join("")}return`
    <span>${d(e.traffic)}</span>
    <span>${e.rules.toLocaleString()} rules</span>
    <span>${d(ct(e))}</span>
  `}function ut(e){let t=Ue(e.subscriptionUserinfo);return t?.percent!=null?t.percent:0}var gt=[{id:"select",label:"Select",icon:"check",needsInactive:!0},{id:"open-web",label:"Open web page",icon:"home",remoteOnly:!1,needsHomeWeb:!0},{id:"edit",label:"Edit",icon:"edit"},{id:"edit-external",label:"Edit externally",icon:"edit"},{id:"update",label:"Update",icon:"refresh",remoteOnly:!0},{id:"reveal",label:"Show in folder",icon:"folder"},{id:"diff",label:"Diff",icon:"diff",remoteOnly:!0},{id:"proxies",label:"Edit proxies section",icon:"send"},{id:"rules",label:"Edit rules section",icon:"rules"},{id:"copy",label:"Copy",icon:"copy"},{id:"qrcode",label:"QRCode",icon:"qr",remoteOnly:!0},{id:"parsers",label:"Parsers",icon:"tree",remoteOnly:!0},{id:"run-script",label:"Run script",icon:"code"},{id:"settings",label:"Settings",icon:"gear"},{id:"delete",label:"Delete",icon:"trash",danger:!0}];function ft(e){let t={check:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9.2 16.6 4.8 12.2l1.4-1.4 3 3 8.6-8.6 1.4 1.4-10 10z"/></svg>',home:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 3.2 3.8 10.2v9.6h5.4v-5.4h5.6v5.4h5.4v-9.6L12 3.2z"/></svg>',edit:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M4.5 16.9 15.8 5.6l2.6 2.6L7.1 19.5H4.5v-2.6zm14.3-11.7 1.5 1.5c.4.4.4 1 0 1.4l-1.2 1.2-2.6-2.6 1.2-1.2c.4-.4 1-.4 1.4 0z"/></svg>',refresh:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 5a7 7 0 0 1 6.3 4H16v2h5.5V5.5H19v1.7A9 9 0 1 0 21 12h-2a7 7 0 1 1-7-7z"/></svg>',folder:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3.5 6.5A2 2 0 0 1 5.5 4.5h4l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2v-11z"/></svg>',diff:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M7 4h2v5H7V4zm0 11h2v5H7v-5zm8-7.5 3.5 3.5L15 14.5V12h-4v-2h4V7.5zM5 10h6v2H5v-2z"/></svg>',send:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3.2 11.2 20 3.5 12.3 20.8l-1.7-6.4-7.4-3.2zm4.4 2.3 4.2 1.8 3.3-7.4-7.5 5.6z"/></svg>',rules:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M5 5h14v2H5V5zm0 6h14v2H5v-2zm0 6h10v2H5v-2z"/></svg>',copy:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M8 7h10v12H8V7zm-3 3H4V4h11v2H5v4zm3-1h2v10h8v2H8V9z"/></svg>',qr:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M4 4h7v7H4V4zm2 2v3h3V6H6zm7-2h7v7h-7V4zm2 2v3h3V6h-3zM4 13h7v7H4v-7zm2 2v3h3v-3H6zm9 0h2v2h-2v-2zm4 0h2v2h-2v-2zm-4 4h2v2h-2v-2zm2 2h4v2h-4v-2zm2-4h2v4h-2v-4z"/></svg>',tree:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M10 3h4v4h-4V3zm-5 7h4v4H5v-4zm10 0h4v4h-4v-4zM7 13h2v3h6v-3h2v5H7v-5z"/></svg>',code:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="m8.2 7.2 1.4 1.4L6.8 12l2.8 3.4-1.4 1.4L4 12l4.2-4.8zm7.6 0L20 12l-4.2 4.8-1.4-1.4 2.8-3.4-2.8-3.4 1.4-1.4z"/></svg>',gear:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M11 3h2l.4 2.2a6.8 6.8 0 0 1 1.8.8l2-1.1 1.4 1.4-1.1 2a6.8 6.8 0 0 1 .8 1.8L20.5 11v2l-2.2.4a6.8 6.8 0 0 1-.8 1.8l1.1 2-1.4 1.4-2-1.1a6.8 6.8 0 0 1-1.8.8L13 20.5h-2l-.4-2.2a6.8 6.8 0 0 1-1.8-.8l-2 1.1-1.4-1.4 1.1-2a6.8 6.8 0 0 1-.8-1.8L3.5 13v-2l2.2-.4a6.8 6.8 0 0 1 .8-1.8l-1.1-2 1.4-1.4 2 1.1a6.8 6.8 0 0 1 1.8-.8L11 3zm1 6.5A2.5 2.5 0 1 0 12 14a2.5 2.5 0 0 0 0-5z"/></svg>',trash:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9 4h6l1 2h4v2H4V6h4l1-2zm1 5h2v9h-2V9zm4 0h2v9h-2V9zM7 9h2v9H7V9z"/></svg>'};return t[e]??t.gear}function L(){s.profileContextMenu=null,s.glassDialog=null,_()}function ht(e,t,a){s.glassDialog=null,s.profileContextMenu={id:e,x:t,y:a},_()}function _(){let e=document.getElementById("glass-menu-root");if(!e)return;let t=[];if(s.profileContextMenu){let a=s.profiles.find(o=>o.id===s.profileContextMenu.id);if(a){let o=!!a.sourceUrl,n=gt.filter(c=>!(c.needsHomeWeb&&!a.homeWeb||c.remoteOnly&&!o||c.needsInactive&&a.active)).map(c=>`
        <button type="button" class="glass-menu-item ${c.danger?"danger":""}" data-profile-menu="${c.id}" data-profile-id="${d(a.id)}">
          <span class="glass-menu-icon">${ft(c.icon)}</span>
          <span>${d(c.label)}</span>
        </button>
      `).join("");t.push(`
        <div class="glass-menu-backdrop" data-glass-dismiss></div>
        <div class="glass-menu" role="menu" style="left:${Math.round(s.profileContextMenu.x)}px;top:${Math.round(s.profileContextMenu.y)}px">
          <div class="glass-menu-scroll" data-glass-menu-scroll>
            ${n}
          </div>
          <div class="glass-menu-more" data-glass-menu-more hidden>
            <span>scroll to view more</span>
            <span aria-hidden="true">\u25BE</span>
          </div>
        </div>
      `)}}if(s.glassDialog){let a=s.glassDialog,o=a.id?s.profiles.find(r=>r.id===a.id):null;if(o&&a.kind==="copy")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Copy profile">
          <h3>Copy profile</h3>
          <label>Name<input data-glass-copy-name value="${d(`${o.name} copy`)}" /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-copy-confirm="${d(o.id)}">Copy</button>
          </div>
        </div>
      `);else if(o&&a.kind==="settings")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Edit profile information">
          <h3>Edit profile information</h3>
          <label>Name<input data-glass-settings-name value="${d(o.name)}" /></label>
          <label>URL<input data-glass-settings-url value="${d(o.sourceUrl??"")}" placeholder="https://..." /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-settings-confirm="${d(o.id)}">Save</button>
          </div>
        </div>
      `);else if(o&&a.kind==="delete")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Delete profile">
          <h3>Delete profile</h3>
          <p class="glass-dialog-copy">Are you sure to delete \u201C${d(o.name)}\u201D? This removes the managed YAML file.</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>No</button>
            <button type="button" class="glass-btn danger" data-glass-delete-confirm="${d(o.id)}">Yes</button>
          </div>
        </div>
      `);else if(a.kind==="reset-settings")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Reset settings">
          <h3>Reset all settings</h3>
          <p class="glass-dialog-copy">Reset Clash for Mac settings to defaults? Imported profile files are kept, but the active profile pointer and runtime toggles reset.</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>No</button>
            <button type="button" class="glass-btn danger" data-glass-reset-confirm>Yes</button>
          </div>
        </div>
      `);else if(a.kind==="geoip")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Update GeoIP database">
          <h3>Update GeoIP database</h3>
          <p class="glass-dialog-copy">Leave URL blank to use MetaCubeX geoip.metadb.</p>
          <label>URL<input data-glass-geoip-url placeholder="https://..." value="" /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-geoip-confirm>Update</button>
          </div>
        </div>
      `);else if(a.kind==="preview-config")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="Runtime config preview">
          <h3>Runtime config preview</h3>
          <pre class="glass-code">${d(a.payload??"")}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
            <button type="button" class="glass-btn" data-glass-copy-text>Copy</button>
          </div>
        </div>
      `);else if(a.kind==="network-interfaces"){let r=(a.payload??[]).map(n=>`
        <tr>
          <td>${d(n.service)}</td>
          <td>${d(n.bsd_device??n.bsdDevice??"\u2014")}</td>
          <td>${d(n.service_type??n.serviceType??"\u2014")}</td>
          <td>${n.is_default_route||n.isDefaultRoute?"default":""}</td>
        </tr>`).join("");t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="Network interfaces">
          <h3>Network interfaces</h3>
          <p class="glass-dialog-copy">Default route: ${d(a.defaultRoute??"unknown")}</p>
          <div class="glass-table-wrap"><table class="glass-table"><thead><tr><th>Service</th><th>Device</th><th>Type</th><th></th></tr></thead><tbody>${r||'<tr><td colspan="4">No services</td></tr>'}</tbody></table></div>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button></div>
        </div>
      `)}else if(a.kind==="bind-address")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Bind address">
          <h3>Bind address</h3>
          <p class="glass-dialog-copy">Use 127.0.0.1 for localhost only, * for all interfaces, or a specific IP.</p>
          <label>Address<input data-glass-bind-address value="${d(a.payload??"*")}" /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-bind-confirm>Save</button>
          </div>
        </div>
      `);else if(a.kind==="dns-query")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="DNS query">
          <h3>Resolve via Clash core</h3>
          <label>Name<input data-glass-dns-name value="${d(a.payload?.name??"www.gstatic.com")}" /></label>
          <label>Type<input data-glass-dns-type value="${d(a.payload?.type??"A")}" /></label>
          <pre class="glass-code">${d(a.payload?.result??"Enter a name and Query.")}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
            <button type="button" class="glass-btn" data-glass-dns-confirm>Query</button>
          </div>
        </div>
      `);else if(a.kind==="script-test")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Script test">
          <h3>Script mode test</h3>
          <p class="glass-dialog-copy">mihomo does not expose a dedicated Script-eval REST API. Switch mode to Script and use Rules / Connections for live match visibility. Optional: open Rules now.</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
            <button type="button" class="glass-btn" data-glass-open-rules>Open Rules</button>
          </div>
        </div>
      `);else if(a.kind==="edit-mixin")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="Edit Mixin">
          <h3>Edit Mixin content</h3>
          <textarea class="glass-textarea" data-glass-mixin-yaml rows="16" spellcheck="false">${d(a.payload??"")}</textarea>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-mixin-confirm>Save</button>
          </div>
        </div>
      `);else if(a.kind==="tun-settings"){let r=a.payload??{};t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="TUN settings">
          <h3>TUN settings</h3>
          <label>Stack
            <select data-glass-tun-stack>
              ${["mixed","gvisor","system","lwip"].map(n=>`<option value="${n}" ${r.stack===n?"selected":""}>${n}</option>`).join("")}
            </select>
          </label>
          <label class="glass-check"><input type="checkbox" data-glass-tun-auto-route ${r.autoRoute?"checked":""} /> auto-route</label>
          <label class="glass-check"><input type="checkbox" data-glass-tun-strict-route ${r.strictRoute?"checked":""} /> strict-route</label>
          <label>DNS hijack (one per line)<textarea data-glass-tun-dns-hijack rows="4" spellcheck="false">${d(r.dnsHijack??`any:53
[::]:53`)}</textarea></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-tun-settings-confirm>Save</button>
          </div>
        </div>
      `)}else a.kind==="tun-reset-dns"?t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Restore DNS">
          <h3>Restore DNS after TUN off</h3>
          <p class="glass-dialog-copy">These servers are applied with networksetup when you click Apply (CFW manage_history). Use Empty to clear overrides.</p>
          <label>DNS servers<textarea data-glass-restore-dns rows="5" spellcheck="false">${d(a.payload??"Empty")}</textarea></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn ghost" data-glass-restore-dns-save>Save</button>
            <button type="button" class="glass-btn" data-glass-restore-dns-apply>Apply now</button>
          </div>
        </div>
      `):a.kind==="service-mode-manage"?t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Service Mode">
          <h3>Service Mode</h3>
          <p class="glass-dialog-copy">Status: ${d(Q(s.serviceModeStatus))}</p>
          <div class="glass-dialog-actions column">
            <button type="button" class="glass-btn" data-glass-service-install>Install / Enable</button>
            <button type="button" class="glass-btn ghost" data-glass-service-uninstall>Uninstall / Disable</button>
            <button type="button" class="glass-btn ghost" data-glass-service-login-items>Open Login Items</button>
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
          </div>
        </div>
      `):a.kind==="info"&&t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Info">
          <h3>${d(a.payload?.title??"Info")}</h3>
          <p class="glass-dialog-copy">${d(a.payload?.body??"")}</p>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button></div>
        </div>
      `)}e.innerHTML=t.join(""),mt(),vt()}function mt(){let e=document.querySelector(".glass-menu");if(!e||!s.profileContextMenu)return;let t=10,a=e.getBoundingClientRect(),o=s.profileContextMenu.x,r=s.profileContextMenu.y;o+a.width>window.innerWidth-t&&(o=Math.max(t,window.innerWidth-a.width-t)),r+a.height>window.innerHeight-t&&(r=Math.max(t,window.innerHeight-a.height-t)),e.style.left=`${Math.round(o)}px`,e.style.top=`${Math.round(r)}px`;let n=e.querySelector("[data-glass-menu-scroll]"),c=e.querySelector("[data-glass-menu-more]");if(n&&c){let l=()=>{let u=n.scrollHeight>n.clientHeight+2,f=n.scrollTop+n.clientHeight>=n.scrollHeight-2;c.hidden=!u||f};n.addEventListener("scroll",l,{passive:!0}),l()}}function vt(){document.querySelectorAll("[data-glass-dismiss]").forEach(t=>{t.addEventListener("click",()=>L())}),document.querySelectorAll("[data-profile-menu]").forEach(t=>{t.addEventListener("click",async a=>{let o=a.currentTarget.dataset.profileMenu,r=a.currentTarget.dataset.profileId;s.profileContextMenu=null,_();try{await Ne(o,r)}catch(n){i("error","profile",`${o} failed: ${n.message??String(n)}`)}g()})}),document.querySelectorAll("[data-glass-copy-confirm]").forEach(t=>{t.addEventListener("click",async a=>{let o=a.currentTarget.dataset.glassCopyConfirm,r=document.querySelector("[data-glass-copy-name]")?.value?.trim();if(r){try{let n=await p("read_profile_text",{id:o}),c=await p("import_profile_text",{name:r,body:n.body,activate:!1});await $(),L(),i("info","profile",`Copied profile to ${c.name}`)}catch(n){i("error","profile",`Copy failed: ${n.message??String(n)}`)}g()}})}),document.querySelectorAll("[data-glass-settings-confirm]").forEach(t=>{t.addEventListener("click",async a=>{let o=a.currentTarget.dataset.glassSettingsConfirm,r=document.querySelector("[data-glass-settings-name]")?.value?.trim()??"",n=document.querySelector("[data-glass-settings-url]")?.value?.trim()??"";try{await p("update_profile_info",{id:o,name:r,url:n}),await $(),L(),i("info","profile",`Profile settings saved: ${r}`)}catch(c){i("error","profile",`Settings failed: ${c.message??String(c)}`)}g()})}),document.querySelectorAll("[data-glass-delete-confirm]").forEach(t=>{t.addEventListener("click",async a=>{a.preventDefault(),a.stopPropagation();let o=a.currentTarget.dataset.glassDeleteConfirm,r=s.profiles.find(n=>n.id===o);try{let n=await p("delete_profile",{id:o});await $(),L(),i(n?"warning":"info","profile",n?`Profile deleted: ${r?.name??o}`:`Profile already missing: ${o}`)}catch(n){i("error","profile",`Delete failed: ${n.message??String(n)}`)}g()})}),document.querySelectorAll("[data-glass-reset-confirm]").forEach(t=>{t.addEventListener("click",async a=>{a.preventDefault(),a.stopPropagation();try{let o=await p("reset_settings_snapshot");v(o),await $(),L(),i("warning","settings","cfw-settings.yaml reset to defaults")}catch(o){i("error","settings",`Reset failed: ${o.message??String(o)}`)}g()})}),document.querySelectorAll("[data-glass-geoip-confirm]").forEach(t=>{t.addEventListener("click",async a=>{if(a.preventDefault(),a.stopPropagation(),s.geoipUpdating)return;let o=document.querySelector("[data-glass-geoip-url]")?.value?.trim()??"";L(),s.geoipUpdating=!0,g();try{let r=await p("update_geoip_database",{url:o||null});s.geoipStatus=r.status,i("info","geoip",`Updated ${r.status.file_name} (${x(r.bytes)}) from ${r.source_url}`)}catch(r){i("warning","geoip",`GeoIP update failed: ${r.message??String(r)}`)}finally{s.geoipUpdating=!1,g()}})}),document.querySelectorAll("[data-glass-copy-text]").forEach(t=>{t.addEventListener("click",async()=>{let a=s.glassDialog?.payload??document.querySelector(".glass-code")?.textContent??"";try{await navigator.clipboard.writeText(String(a)),i("info","clipboard","Copied dialog text")}catch(o){i("warning","clipboard",o.message??String(o))}})}),document.querySelectorAll("[data-glass-bind-confirm]").forEach(t=>{t.addEventListener("click",async()=>{let a=document.querySelector("[data-glass-bind-address]")?.value?.trim()??"";try{let o=await p("set_bind_address",{address:a});v(o),L(),i("info","settings",`Bind address set to ${a}`),k().active&&await p("apply_active_profile")}catch(o){i("warning","settings",`Bind address failed: ${o.message??String(o)}`)}g()})}),document.querySelectorAll("[data-glass-dns-confirm]").forEach(t=>{t.addEventListener("click",async()=>{let a=document.querySelector("[data-glass-dns-name]")?.value?.trim()??"",o=document.querySelector("[data-glass-dns-type]")?.value?.trim()||"A";try{let r=await p("dns_query",{name:a,record_type:o,recordType:o});s.glassDialog={kind:"dns-query",payload:{name:a,type:o,result:JSON.stringify(r,null,2)}},_()}catch(r){s.glassDialog={kind:"dns-query",payload:{name:a,type:o,result:String(r.message??r)}},_()}})}),document.querySelectorAll("[data-glass-open-rules]").forEach(t=>{t.addEventListener("click",async()=>{L(),s.activePage="rules",await ue(),g()})}),document.querySelectorAll("[data-glass-mixin-confirm]").forEach(t=>{t.addEventListener("click",async()=>{let a=document.querySelector("[data-glass-mixin-yaml]")?.value??"";try{let o=await p("write_settings_snapshot",{settings:{...S(),mixin_yaml:a,mixinYaml:a}});if(v(o),s.mixinYaml=a,L(),i("info","settings","Mixin YAML saved"),s.toggles.mixin&&k().active){let r=await p("apply_active_profile");i("info","settings",`Mixin reapplied (${x(r.bytes??0)})`)}}catch(o){i("warning","settings",`Mixin save failed: ${o.message??String(o)}`)}g()})}),document.querySelectorAll("[data-glass-tun-settings-confirm]").forEach(t=>{t.addEventListener("click",async()=>{let a=document.querySelector("[data-glass-tun-stack]")?.value??"mixed",o=!!document.querySelector("[data-glass-tun-auto-route]")?.checked,r=!!document.querySelector("[data-glass-tun-strict-route]")?.checked,n=document.querySelector("[data-glass-tun-dns-hijack]")?.value??`any:53
[::]:53`;try{let c=S(),l=await p("write_settings_snapshot",{settings:{...c,"tun-stack":a,tunStack:a,"tun-auto-route":o,tunAutoRoute:o,"tun-strict-route":r,tunStrictRoute:r,"tun-dns-hijack":n,tunDnsHijack:n}});if(v(l),L(),i("info","tun",`TUN settings saved (stack=${a})`),s.toggles.tunMode)try{await p("reapply_runtime_config"),i("info","tun","Runtime config reapplied (root core respawn when TUN owns core)")}catch(u){i("warning","tun",`Reapply after TUN settings failed: ${u.message??String(u)}`)}}catch(c){i("warning","tun",`TUN settings failed: ${c.message??String(c)}`)}g()})});let e=async t=>{let a=document.querySelector("[data-glass-restore-dns]")?.value??"Empty";try{let o=S(),r=await p("write_settings_snapshot",{settings:{...o,"restore-dns-servers":a,restoreDnsServers:a}});if(v(r),t){let n=await p("apply_restore_dns_servers",{servers:a});i("info","dns",n)}else i("info","dns","Restore DNS list saved");L()}catch(o){i("warning","dns",o.message??String(o))}g()};document.querySelectorAll("[data-glass-restore-dns-save]").forEach(t=>{t.addEventListener("click",()=>e(!1))}),document.querySelectorAll("[data-glass-restore-dns-apply]").forEach(t=>{t.addEventListener("click",()=>e(!0))}),document.querySelectorAll("[data-glass-service-install]").forEach(t=>{t.addEventListener("click",async()=>{try{let a=await p("enable_service_mode");s.serviceModeStatus=a,i("info","service",`Service Mode: ${Q(a)}`)}catch(a){i("warning","service",a.message??String(a))}L(),g()})}),document.querySelectorAll("[data-glass-service-uninstall]").forEach(t=>{t.addEventListener("click",async()=>{try{await p("disable_service_mode"),s.serviceModeStatus=await p("service_mode_status"),i("info","service","Service Mode disabled")}catch(a){i("warning","service",a.message??String(a))}L(),g()})}),document.querySelectorAll("[data-glass-service-login-items]").forEach(t=>{t.addEventListener("click",async()=>{try{await p("open_login_items_settings"),i("info","service","Opened Login Items settings")}catch(a){i("warning","service",a.message??String(a))}})})}async function Ne(e,t){let a=s.profiles.find(o=>o.id===t);if(!a)throw new Error(`profile not found: ${t}`);switch(e){case"select":await ye(t);return;case"open-web":{if(!a.homeWeb)throw new Error("no profile-web-page-url for this subscription");await p("open_external_url",{url:a.homeWeb}),i("info","profile",`Opened web page for ${a.name}`);return}case"edit":await I(t,"edit"),i("info","profile",`edit editor opened for ${a.name}`);return;case"proxies":await I(t,"edit","proxies"),i("info","profile",`proxies section editor opened for ${a.name}`);return;case"rules":await I(t,"edit","rules"),i("info","profile",`rules section editor opened for ${a.name}`);return;case"edit-external":await p("open_profile_externally",{id:t}),i("info","profile",`Opened ${a.name} externally`);return;case"update":{if(!a.sourceUrl)throw new Error("local profile has no subscription URL");let o=a.active,r=await p("update_profile",{id:t});await $(),o&&await p("apply_active_profile"),i("info","profile",`${r.name} subscription updated${o?" and config.yaml reapplied":""}`);return}case"reveal":await p("reveal_profile",{id:t}),i("info","profile",`Show in folder: ${a.name}`);return;case"diff":await I(t,"diff"),i("info","profile",`Diff opened for ${a.name}`);return;case"copy":s.glassDialog={kind:"copy",id:t},_();return;case"qrcode":await I(t,"qrcode"),i("info","profile",`QRCode opened for ${a.name}`);return;case"parsers":await I(t,"parsers"),i("info","profile",`Parsers opened for ${a.name}`);return;case"run-script":await I(t,"parsers"),a.active?(await p("apply_active_profile"),i("info","profile",`Run script: reapplied parsers/mixin for active profile ${a.name}`)):i("info","profile",`Run script: parser pipeline runs on apply; select ${a.name} to execute against config.yaml`);return;case"settings":s.glassDialog={kind:"settings",id:t},_();return;case"delete":s.glassDialog={kind:"delete",id:t},_();return;default:throw new Error(`unknown profile menu action: ${e}`)}}function yt(){return`
    <div class="profiles-layout">
      <section class="cfw-profile-remote">
        <div class="cfw-url-box">
          <input data-profile-url placeholder="Download from a URL" aria-label="Profile URL" />
          <button class="paste-icon" data-action="paste-profile-url" title="Paste URL">\u25A3</button>
        </div>
        <button class="cfw-big-button" data-action="import-profile">Download</button>
        <button class="cfw-big-button" data-action="update-all-profiles">Update All</button>
        <button class="cfw-big-button" data-action="import-profile-file">Import</button>
        <input class="profile-file-hidden" data-profile-file type="file" accept=".yaml,.yml,text/yaml,application/x-yaml" aria-label="Local profile YAML" />
      </section>

      <section class="cfw-profile-list">
        ${s.profiles.length?s.profiles.map(e=>`
          <article class="cfw-profile-card ${e.active?"active":""}" data-profile-card="${d(e.id)}">
            <i></i>
            <div class="profile-card-main">
              <h3>${d(e.name)}</h3>
              <p>${d(e.sourceUrl?lt(e.sourceUrl):"local file")} (${d(e.updated)})</p>
              <div class="profile-usage">
                ${pt(e)}
              </div>
              <div class="profile-progress" title="${e.subscriptionUserinfo?d(e.subscriptionUserinfo):"No subscription usage quota"}"><b style="width:${ut(e).toFixed(1)}%"></b></div>
            </div>
            <div class="profile-card-primary">
              ${e.sourceUrl?`<button data-update-profile="${d(e.id)}" title="Update subscription">\u27F3</button>`:`<button data-profile-action="edit" data-profile-id="${d(e.id)}" title="Edit local profile">\u2039\u203A</button>`}
            </div>
            <div class="profile-card-secondary">
              ${e.active?"":`<button data-profile="${d(e.id)}" title="Select profile">\u2713</button>`}
              <button data-profile-action="diff" data-profile-id="${d(e.id)}" title="Diff">\u224B</button>
              <button data-profile-action="qrcode" data-profile-id="${d(e.id)}" ${e.sourceUrl?"":"disabled"} title="QRCode">\u25A6</button>
              <button data-reveal-profile="${d(e.id)}" title="Show in Finder">\u2315</button>
              <button data-delete-profile="${d(e.id)}" title="Delete">\xD7</button>
            </div>
          </article>
        `).join(""):`
          <div class="empty-profile-state">
            <p>No profiles found in the managed profiles directory.</p>
            <button data-action="migrate-legacy-profiles">Import CFW Profiles</button>
          </div>
        `}
      </section>
      ${bt()}
    </div>
  `}function bt(){let e=s.profileInspector;if(!e)return"";let t=e.profile??{},a=`${t.name??e.id} \xB7 ${e.mode}`,o=t.source_url??t.sourceUrl??null,r=t.body?[...t.body.matchAll(/^([A-Za-z0-9_-]+):/gm)].map(c=>c[1]).filter(c=>c.toLowerCase().includes("parser")):[],n="";return e.mode==="diff"?n=`
      <div class="profile-diff-grid">
        <div><p class="label">Managed YAML</p><pre>${d(t.body??"")}</pre></div>
        <div><p class="label">Generated config.yaml preview</p><pre>${d(t.generated_body??"")}</pre></div>
      </div>
    `:e.mode==="edit"?n=`
      <textarea class="profile-editor" data-profile-editor spellcheck="false">${d(t.body??"")}</textarea>
      <div class="row-actions">
        <button class="button" data-action="save-profile-editor">Save YAML</button>
        <button class="button ghost" data-action="close-profile-inspector">Close</button>
      </div>
    `:e.mode==="qrcode"?n=e.svg?`<div class="profile-qr">${e.svg}</div><p class="muted">${d(o??"")}</p>`:`<p class="empty">${d(e.error??"This local profile has no subscription URL.")}</p>`:e.mode==="parsers"?n=`
      <dl class="detail-grid">
        <div><dt>Parser keys</dt><dd>${r.length?r.map(d).join(", "):"none in this profile"}</dd></div>
        <div><dt>Execution</dt><dd>Parser scripts are treated as config transformation metadata only; arbitrary script execution is not enabled from the dashboard.</dd></div>
      </dl>
    `:n=`
      <dl class="detail-grid">
        <div><dt>ID</dt><dd>${d(t.id??e.id)}</dd></div>
        <div><dt>Path</dt><dd>${d(t.path??"")}</dd></div>
        <div><dt>Active</dt><dd>${t.active?"yes":"no"}</dd></div>
        <div><dt>Source URL</dt><dd>${d(o??"local file")}</dd></div>
      </dl>
    `,`
    <section class="panel profile-inspector">
      <div class="section-heading">
        <div>
          <p class="label">Profile Inspector</p>
          <h3>${d(a)}</h3>
        </div>
        <button class="button ghost" data-action="close-profile-inspector">Close</button>
      </div>
      ${n}
    </section>
  `}function wt(){let e=s.providerBulkActions.has("update-all-providers"),t=s.providerBulkActions.has("health-check-all");return`
    <div class="providers-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">Providers</p>
          <h3>Proxy Providers</h3>
          <p class="muted">Matches the original Proxy Providers / Rule Providers split and keeps Update All / Health Check All visible.</p>
        </div>
        <div class="toolbar-actions">
          <button class="button" data-action="update-all-providers" ${e?"disabled":""}>${e?"Updating...":"Update All"}</button>
          <button class="button ghost" data-action="health-check-all" ${t?"disabled":""}>${t?"Checking...":"Health Check All"}</button>
          <button class="button ghost" data-action="open-rules">Rules</button>
        </div>
      </section>

      <section class="provider-section">
        <div class="section-title">Proxy Providers</div>
        ${s.providers.length?s.providers.map(a=>{let o=G("proxy-update",a.name),r=G("proxy-health",a.name),n=s.providerActions.has(o),c=s.providerActions.has(r);return`
            <article class="panel provider-row">
              <div>
                <p class="label">${d(a.vehicle)}</p>
                <h3>${d(a.name)}</h3>
                <p class="muted">${a.proxies} proxies \xB7 ${d(a.health)} \xB7 updated ${d(a.updated)}</p>
              </div>
              <div class="row-actions">
                <button class="button ghost" data-provider-update="${d(a.name)}" ${n?"disabled":""}>${n?"Updating":"Update"}</button>
                <button class="button" data-provider-health="${d(a.name)}" ${c?"disabled":""}>${c?"Checking":"Health Check"}</button>
              </div>
            </article>
          `}).join(""):`
          <article class="panel provider-row empty-state">
            <div>
              <p class="label">Controller</p>
              <h3>No proxy providers loaded</h3>
              <p class="muted">This is now driven by /providers/proxies; no fake provider rows are rendered when Clash has none.</p>
            </div>
          </article>
        `}
      </section>

      <section class="provider-section">
        <div class="section-title">Rule Providers</div>
        ${s.ruleProviders.length?s.ruleProviders.map(a=>{let o=G("rule-update",a.name),r=s.providerActions.has(o);return`
            <article class="panel provider-row">
              <div>
                <p class="label">${d(a.behavior)}</p>
                <h3>${d(a.name)}</h3>
                <p class="muted">${a.rules.toLocaleString()} rules \xB7 updated ${d(a.updated)}</p>
              </div>
              <div class="row-actions">
                <button class="button ghost" data-rule-provider-update="${d(a.name)}" ${r?"disabled":""}>${r?"Updating":"Update"}</button>
              </div>
            </article>
          `}).join(""):`
          <article class="panel provider-row empty-state">
            <div>
              <p class="label">Controller</p>
              <h3>No rule providers loaded</h3>
              <p class="muted">This list is live from /providers/rules and stays empty when the active config has no rule providers.</p>
            </div>
          </article>
        `}
      </section>
    </div>
  `}function _t(){let e=Ke();return`
    <div class="logs-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">Diagnostics</p>
          <h3>${e.length} log entries${s.logsPaused?" paused":""}</h3>
        </div>
        <div class="search-box">
          <input value="${d(s.logSearch)}" data-log-search aria-label="Search logs" placeholder="Search logs or regex" />
        </div>
        <div class="segmented">
          ${["all","info","debug","warning","error"].map(t=>`
            <button class="${s.logFilter===t?"selected":""}" data-log-filter="${t}">${t.toUpperCase()}</button>
          `).join("")}
        </div>
        <div class="toolbar-actions">
          <button class="button ghost" data-action="toggle-log-stream">${s.logsPaused?"Start":"Stop"}</button>
          <button class="button ghost" data-action="copy-logs">Copy</button>
          <button class="button ghost" data-action="reveal-logs">Open Folder</button>
          <button class="button ghost" data-action="clear-logs">Clear</button>
        </div>
      </section>

      <section class="panel log-stream">
        ${e.map(t=>`
          <article class="log-line ${d(t.level)}">
            <time>${d(t.time)}</time>
            <b>${d(t.level)}</b>
            <span>${d(t.source)}</span>
            <p>
              ${d(t.message)}
              ${(t.fields??[]).length?`<small>${t.fields.map(a=>`${d(a.key)}=${d(a.value)}`).join(" \xB7 ")}</small>`:""}
            </p>
          </article>
        `).join("")||'<p class="empty">No logs for this filter.</p>'}
      </section>
    </div>
  `}function xt(e){let t=e.metadata?.processPath??e.metadata?.process_path??e.processPath??"";if(!t)return"\u2014";let a=String(t).split(/[/\\]/).filter(Boolean);return a[a.length-1]||String(t)}function Fe(e,t){return`
    <article class="cfw-conn-item${t?" with-process":""}" data-connection-id="${d(e.id)}">
      <div class="conn-main">
        <h3>${d(e.host)}</h3>
        <div class="conn-chips">
          <span class="conn1">${d(e.rule||"MATCH")}</span>
          ${(e.chains??[]).slice(0,4).map((a,o)=>`<span class="conn${o%6+2}">${d(a)}</span>`).join("")}
          <span class="conn7">${d(e.metadata?.network??e.metadata?.type??"tcp")}</span>
        </div>
      </div>
      ${t?`<div class="conn-process" title="${d(e.metadata?.processPath??e.metadata?.process_path??"")}">${d(xt(e))}</div>`:""}
      <div class="conn-traffic">
        <b data-conn-up>\u2191 ${d(e.upload)}</b>
        <b data-conn-down>\u2193 ${d(e.download)}</b>
        <small data-conn-speed>${d(e.speed??"0 B/s")}</small>
      </div>
      <div class="conn-actions">
        <button data-connection-detail="${d(e.id)}">Info</button>
        <button data-close-connection="${d(e.id)}" ${s.closingConnectionIds.has(e.id)?"disabled":""}>${s.closingConnectionIds.has(e.id)?"Closing":"Close"}</button>
      </div>
    </article>
  `}function St(){let e=Te(),t=s.connections.find(n=>n.id===s.connectionDetailId),a=x(s.connectionStream.uploadTotal),o=x(s.connectionStream.downloadTotal),r=s.toggles.showProcess!==!1;return w.connectionRowEls=null,`
    <div class="connections-layout" data-connections-root>
      <section class="cfw-conn-header">
        <h1>Connections</h1>
        <div class="cfw-conn-search">
          <span>\u25CF</span>
          <input value="${d(s.connectionSearch)}" data-connection-search aria-label="Search connections" placeholder="Search connections" />
          ${s.connectionSearch?'<button data-action="clear-connection-search">\xD7</button>':""}
        </div>
        <strong data-conn-totals>Total: \u2191 ${a} \u2193 ${o}</strong>
      </section>

      <section class="cfw-conn-controls">
        ${[["upload","\u21A5 \u25D2"],["download","\u21A7 \u25D2"],["upload","\u21A5 \u25A5"],["download","\u21A7 \u25A5"],["age","\u25F7"],["host","\u25AD"]].map(([n,c])=>`
          <button class="${s.connectionSort===n?"selected":""}" data-connection-sort="${n}">${c}</button>
        `).join("")}
        <span></span>
        <button class="danger" data-action="toggle-connection-stream">${s.connectionPaused?"Resume":"Pause"}</button>
        <button class="danger" data-action="close-all" data-conn-close-all ${s.closingAllConnections?"disabled":""}>${s.closingAllConnections?"Closing...":`Close All (${e.length})`}</button>
      </section>

      <section class="cfw-conn-scroll" data-conn-scroll>
        ${e.map(n=>Fe(n,r)).join("")}
      </section>
      ${t?He(t):""}
    </div>
  `}function $t(){let e=document.querySelector("[data-connections-root]"),t=document.querySelector("[data-conn-scroll]");if(!e||!t||s.activePage!=="connections"){g();return}let a=Te(),o=s.toggles.showProcess!==!1,r=e.querySelector("[data-conn-totals]");r&&(r.textContent=`Total: \u2191 ${x(s.connectionStream.uploadTotal)} \u2193 ${x(s.connectionStream.downloadTotal)}`);let n=e.querySelector("[data-conn-close-all]");n&&(n.disabled=!!s.closingAllConnections,n.textContent=s.closingAllConnections?"Closing...":`Close All (${a.length})`),w.connectionRowEls instanceof Map||(w.connectionRowEls=new Map,t.querySelectorAll("[data-connection-id]").forEach(h=>{w.connectionRowEls.set(h.getAttribute("data-connection-id"),h)}));let c=new Set(a.map(h=>h.id));for(let[h,P]of[...w.connectionRowEls.entries()])c.has(h)||(P.remove(),w.connectionRowEls.delete(h));let l=document.createDocumentFragment(),u=!1;a.forEach((h,P)=>{let C=w.connectionRowEls.get(h.id);if(!C){let K=document.createElement("div");K.innerHTML=Fe(h,o).trim(),C=K.firstElementChild,w.connectionRowEls.set(h.id,C),u=!0,l.appendChild(C);return}let q=C.querySelector("[data-conn-up]"),B=C.querySelector("[data-conn-down]"),T=C.querySelector("[data-conn-speed]");q&&(q.textContent=`\u2191 ${h.upload}`),B&&(B.textContent=`\u2193 ${h.download}`),T&&(T.textContent=h.speed??"0 B/s");let ge=C.querySelector("[data-close-connection]");if(ge){let K=s.closingConnectionIds.has(h.id);ge.disabled=K,ge.textContent=K?"Closing":"Close"}let be=t.children[P];!u&&be!==C&&t.insertBefore(C,be??null)}),l.childNodes.length&&t.appendChild(l);let f=s.connections.find(h=>h.id===s.connectionDetailId),b=e.querySelector(".modal-backdrop");f&&!b?(e.insertAdjacentHTML("beforeend",He(f)),ze()):!f&&b&&b.remove()}function kt(){w.connectionsPatchFrame===null&&(w.connectionsPatchFrame=window.requestAnimationFrame(()=>{w.connectionsPatchFrame=null,$t()}))}function He(e){let t=e.metadata??{};return`
    <div class="modal-backdrop" data-action="close-connection-detail">
      <section class="connection-info-modal" data-modal-stop>
        <div class="modal-head">
          <h2>Connection Info</h2>
          <button data-action="close-connection-detail">\xD7</button>
        </div>
        <dl>
          ${[["Host",e.host],["Rule",e.rule],["Chains",(e.chains??[]).join(" / ")],["Upload",e.upload],["Download",e.download],["Speed",e.speed],...Object.entries(t).filter(([,o])=>o!=null&&o!=="")].map(([o,r])=>`
            <div>
              <dt>${d(o)}</dt>
              <dd>${d(String(r??""))}</dd>
              <button data-copy-text="${d(String(r??""))}">Copy</button>
            </div>
          `).join("")}
        </dl>
      </section>
    </div>
  `}function Ct(){let e=Qe();return`
    <div class="rules-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">Router</p>
          <h3>${e.length} / ${s.rules.length} active rule entries</h3>
          <p class="muted">Live data from Clash controller /rules, including rule type, payload, proxy target and hit counters when exposed by the core.</p>
        </div>
        <div class="search-box">
          <input value="${d(s.ruleSearch)}" data-rule-search aria-label="Search rules" placeholder="Search rules" />
        </div>
        <div class="toolbar-actions">
          <button class="button ghost" data-action="reload-rules">Reload Rules</button>
        </div>
      </section>

      <section class="panel table-panel">
        <div class="connection-table">
          <div class="table-row rule-head">
            <span>#</span><span>Type</span><span>Payload</span><span>Proxy</span><span>Hits</span>
          </div>
          ${e.map(t=>`
            <div class="table-row rule-row">
              <span>${d(t.index)}</span>
              <span>${d(t.type)}</span>
              <span>${d(t.payload||"-")}</span>
              <span>${d(t.proxy)}</span>
              <span>${d(t.hits)}</span>
            </div>
          `).join("")||'<p class="empty">No rules loaded from the controller.</p>'}
        </div>
      </section>
    </div>
  `}function N(e,t){return`
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">Settings</p>
          <h3>${d(e)}</h3>
        </div>
      </div>
      <div class="settings-list">${t.join("")}</div>
    </section>
  `}function Pt(){let e=s.networkDiagnostics;if(!e)return N("Network Diagnostics",[y("Default Route","Unavailable","Run inside the Tauri app to inspect macOS service order.")]);let t=e.services??[],a=e.recommended_clash_proxy_services??[],o=[y("Default Route",e.default_route_interface??"unknown","BSD interface used by the active default route."),y("Proxy Target",a.length?a.join(", "):"fallback to active services","System Proxy now prefers the default-route service before touching other services.")];return o.push(...t.map(r=>{let n=[r.proxy?.web,r.proxy?.secure_web,r.proxy?.socks].filter(Boolean),c=n.some(h=>h.managed_by_clash),l=!c&&n.some(h=>h.enabled),u=c?"Clash":l?"External":"Off",f=[r.hardware_port,r.bsd_device].filter(Boolean).join(" / ")||r.service_type||"unknown",b=r.is_default_route?"default route":`order ${r.service_order??"-"}`;return y(r.service,`${u} \xB7 ${f}`,`${b}; bypass ${r.bypass_domains?.length??0} domain(s).`)})),N("Network Diagnostics",o)}function Mt(){return`
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">Mixin</p>
          <h3>YAML Merge Before Apply</h3>
          <p class="muted">When Mixin is enabled, this YAML mapping is recursively merged into generated config.yaml before the core reloads.</p>
        </div>
        ${M("mixin","Mixin","Enable runtime YAML merge.")}
      </div>
      <textarea class="mixin-editor" data-mixin-yaml spellcheck="false" placeholder="dns:
  enable: true
profile:
  store-selected: true">${d(s.mixinYaml??"")}</textarea>
    </section>
  `}function Lt(){return`
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">Profile Parser</p>
          <h3>Safe Parser Script Before Mixin</h3>
          <p class="muted">Runs when previewing or applying profiles. Supported commands: set, delete, append, prepend, append-rule, prepend-rule, merge.</p>
        </div>
        <span class="badge">raw \u2192 parser \u2192 mixin \u2192 runtime</span>
      </div>
      <textarea class="mixin-editor" data-profile-parser-script spellcheck="false" placeholder="prepend-rule DOMAIN-SUFFIX,example.com,DIRECT&#10;set dns.enable true&#10;delete proxy-providers">${d(s.profileParserScript??"")}</textarea>
    </section>
  `}function At(){return`
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">Actions</p>
          <h3>Tray Script & Child Process</h3>
          <p class="muted">Commands run through the typed Rust action runner, not from renderer-side eval.</p>
        </div>
        <div class="toolbar-actions">
          <button class="button ghost" data-action="run-tray-script">Run Tray Script</button>
          <button class="button ghost" data-action="run-child-process">Run Child</button>
        </div>
      </div>
      ${Z("Tray Script",s.trayScript,"/usr/bin/say 'Clash for Mac'","Absolute executable path plus arguments; shell expansion is intentionally disabled.","data-tray-script")}
      ${Z("Child Process",s.childProcessCommand,"/usr/bin/env","Lifecycle command staged for helper/service mode experiments.","data-child-process-command")}
    </section>
  `}function Et(){let e=s.payload.product??D.product;return`
    <div class="feedback-layout">
      <section class="panel hero-panel">
        <div>
          <p class="label">Feedback</p>
          <h3>${d(e.name)} v${d(e.version??"0.3.1")}</h3>
          <p class="muted">Parity target is CFW 0.20.39; this build is the Apple Silicon beta (${d(e.version??"0.3.1")}).</p>
        </div>
        <span class="badge">ARM64 macOS only</span>
      </section>

      <section class="panel">
        <p class="label">Updates</p>
        <h3>Check for Updates</h3>
        <p class="muted">Uses tauri-plugin-updater against GitHub Releases (<code>latest.json</code>).</p>
        <div class="toolbar-actions">
          <button class="button" data-action="check-for-updates">Check for Updates</button>
        </div>
      </section>

      <section class="panel">
        <p class="label">Parity source</p>
        <h3>CFW 0.20.39 (reference)</h3>
        <p class="muted">${d(e.parity_source??"reverse artifact")}</p>
        <dl class="ports-list feedback-list">
          <div><dt>main</dt><dd>reverse/cfw-0.20.39-arm64/asar/main.js</dd></div>
          <div><dt>renderer</dt><dd>reverse/cfw-0.20.39-arm64/asar/renderer.js</dd></div>
          <div><dt>window</dt><dd>850 x 603 min frameless baseline</dd></div>
          <div><dt>routes</dt><dd>general / proxy / provider / log / server / connection / router / setting / about</dd></div>
        </dl>
      </section>
    </div>
  `}function y(e,t,a){return`
    <div class="setting-row">
      <span>
        <b>${d(e)}</b>
        <small>${d(a)}</small>
      </span>
      <strong>${d(t)}</strong>
    </div>
  `}function Z(e,t,a,o,r){return`
    <label class="setting-row setting-control-row">
      <span>
        <b>${d(e)}</b>
        <small>${d(o)}</small>
      </span>
      <input class="setting-input" ${r} value="${d(t??"")}" placeholder="${d(a??"")}" />
    </label>
  `}function Tt(e,t,a,o,r){return`
    <label class="setting-row setting-control-row">
      <span>
        <b>${d(e)}</b>
        <small>${d(o)}</small>
      </span>
      <select class="setting-input" ${r}>
        ${a.map(n=>`<option value="${d(n.value)}" ${n.value===t?"selected":""}>${d(n.label)}</option>`).join("")}
      </select>
    </label>
  `}function le(e,t,a,o,r){return`
    <div class="setting-row">
      <span>
        <b>${d(e)}</b>
        <small>${d(a)}</small>
      </span>
      <span class="setting-action">
        <strong>${d(t)}</strong>
        <button class="button ghost" data-action="${d(o)}">${d(r)}</button>
      </span>
    </div>
  `}function Dt(){let e=s.payload.quality??D.quality,t=e.performance,a=e.stability;return`
    <section class="panel quality-panel">
      <div>
        <p class="label">Quality target</p>
        <h3>Interim quality budgets (target ${t.multiplier_vs_cfw_02039}\xD7 vs CFW 0.20.39)</h3>
        <p class="muted">These are engineering budgets, not yet proven with side-by-side benchmarks on this machine.</p>
      </div>
      <dl class="budget-grid">
        <div><dt>Cold start p95</dt><dd>${t.cold_start_p95_ms} ms</dd></div>
        <div><dt>Page switch p95</dt><dd>${t.page_switch_p95_ms} ms</dd></div>
        <div><dt>Proxy toggle p95</dt><dd>${t.proxy_toggle_p95_ms} ms</dd></div>
        <div><dt>Idle RSS cap</dt><dd>${t.max_idle_rss_mb} MB</dd></div>
        <div><dt>Crash-free sessions</dt><dd>${(a.crash_free_session_rate_basis_points/100).toFixed(2)}%</dd></div>
        <div><dt>Proxy restore</dt><dd>${a.restore_system_proxy_on_exit?"Required":"Missing"}</dd></div>
      </dl>
    </section>
  `}function Rt(){let e=s.payload.platform??D.platform,t=s.settingsSnapshot??m,a=t.settings??m.settings,o=t.paths??m.paths,r=`${a.external_controller_host}:${a.external_controller_port}`,n=a["interface-name"]??a.interfaceName??"",c=s.networkDiagnostics?.default_route_interface??"auto",l=a.theme==="dark"?"dark":"light",u=a.font_family??a.fontFamily??"",f=[["Security",[y("Core Secret",a.secret?"random UUID":"not set","Protect Clash REST API with a random RFC4122 UUID.")]],["Appearance",[Tt("Theme",l,[{value:"light",label:"Light"},{value:"dark",label:"Dark"}],"Persisted app theme applied at boot.","data-theme-setting"),Z("Font",u,"Avenir Next","Override dashboard font family; blank uses the CFW-like default.","data-font-family")]],["System Proxy",[M("systemProxy","System Proxy","Enable macOS system HTTP/HTTPS/SOCKS proxy."),M("proxyDelayIndicator","Tray delay indicator","Show selected-node latency in the menu-bar title/tooltip."),M("usePacScript","Use PAC Script","When System Proxy is on, apply Auto Proxy URL (PAC) instead of manual HTTP/HTTPS/SOCKS."),(()=>{let h=(a.proxy_bypass??[]).join(`
`),P=a.pacScript??a.pac_script??s.pacScript??"";return`
          <label class="setting-row setting-control-row">
            <span>
              <b>Bypass Domains</b>
              <small>One host or CIDR per line. Empty uses the built-in LAN/localhost defaults. Applied when System Proxy turns on (manual mode).</small>
            </span>
            <textarea class="mixin-editor" data-proxy-bypass spellcheck="false" rows="5">${d(h)}</textarea>
          </label>
          <label class="setting-row setting-control-row">
            <span>
              <b>PAC Script</b>
              <small>FindProxyForURL body. Empty generates PROXY/SOCKS5 for the current mixed-port. Written to app-home proxy.pac when Use PAC Script is on.</small>
            </span>
            <textarea class="mixin-editor" data-pac-script spellcheck="false" rows="8" placeholder="function FindProxyForURL(url, host) {&#10;  return &quot;PROXY 127.0.0.1:7890; SOCKS5 127.0.0.1:7890; DIRECT&quot;;&#10;}">${d(P)}</textarea>
          </label>`})()]],["Mixin",[M("mixin","Mixin","Merge YAML/JS mixin before profile apply."),y("Mixin YAML","Editor active","The YAML merge editor below is persisted and applied before config reload.")]],["Proxies",[M("hideUnavailable","Hide timed-out proxies","Hide nodes that failed latency tests (Timeout), matching CFW Show/Hide timed-out proxies."),Z("Delay test URL",a.delayTestUrl??a.delay_test_url??"http://www.gstatic.com/generate_204","http://www.gstatic.com/generate_204","Used by Proxies \u2192 Delay Test against the live controller.","data-delay-test-url")]],["Connections",[M("breakOnProxyChange","Break connections","Disconnect sockets after proxy or profile changes."),M("showProcess","Show Process","Show connection process name from metadata.processPath when the core reports it.")]],["Providers",[y("Use CFW Editor","Profile editor active","Profile YAML edit/diff is built in; provider file editor remains behind controller metadata."),y("Update All","Controller-backed","Proxy and rule providers expose bulk update actions.")]],["Outbound",[Z("Interface Name",n,c,"Bind Clash outbound sockets to a macOS BSD interface; blank keeps Clash automatic.","data-outbound-interface")]],["Child Processes",[y("Processes","Action runner","Spawn child processes through a typed Rust command boundary.")]],["Profiles",[y("Parsers","Safe script active","Apply parser scripts before mixin/runtime config generation."),y("Headers","Captured","Remote imports persist subscription-userinfo and profile-update-interval metadata.")]],["Logs",[y("Request Logs","Preload + stream","Original supports log preload, filters and log-level changes.")]],["SSID",[y("SSID Policy","Not in 0.2.0","CFW could vary proxy/profile by Wi-Fi SSID. Deferred \u2014 this toggle is intentionally unavailable.")]],["Actions",[y("Tray Script","Rust action runner","Run Tray Script action is executable from settings and tray.")]],["Shortcuts",[y("Mode shortcuts","Active","Cmd+1..6, Cmd+G/R/D/S/P/T/M mirror original dashboard shortcuts.")]],["CFW Editor",[y("Diff Editor","Not in 0.2.0","Built-in YAML edit exists on Profiles; Monaco-style side-by-side diff is deferred.")]],["Cache",[le("Fake IP Cache","Controller-backed","Flush Mihomo fake-ip cache through /cache/fakeip/flush.","flush-fake-ip-cache","Flush")]],["Experimental Features",[y("DHCP Server","Not in 0.2.0","CFW macOS DHCP server switch is not shipped in this beta."),M("enableIpv6","IPv6","Expose IPv6 option in generated Clash config.")]]],b=Q(s.serviceModeStatus);return`
    <div class="settings-layout">
      <section class="panel toolbar-panel settings-toolbar">
        <div>
          <p class="label">Settings Store</p>
          <h3>${t.persisted?"cfw-settings.yaml loaded":"Defaults staged"}</h3>
          <p class="muted">${d(o.settings_file)}${t.persisted?"":" will be created on save."}</p>
        </div>
        <div class="toolbar-actions">
          <button class="button ghost danger" data-action="reset-settings">Reset All Settings</button>
          <button class="button" data-action="save-settings">Save Settings</button>
          <button class="button ghost" data-action="reload-settings">Reload From Disk</button>
          <button class="button ghost" data-action="force-quit-app">Force Quit</button>
          <button class="button ghost" data-action="quit-app">Quit</button>
        </div>
      </section>
      ${N("General",[M("startAtLogin","Start at Login","Launch Clash for Mac after login via SMAppService Login Item."),M("silentStart","Silent Start","Start hidden in tray without Dock bounce (Accessory policy)."),M("proxyDelayIndicator","Tray delay indicator","Show current proxy latency in tray quick menu."),le("Updates","GitHub Releases","Check tauri-plugin-updater against the latest signed release.","check-for-updates","Check for Updates")])}
      ${N("Core",[y("mixed-port",String(a.mixed_port),"HTTP, HTTPS and SOCKS entry point."),y("external-controller",r,"Local Clash controller endpoint."),y("secret",a.secret?"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022":"empty","Controller secret stored in cfw-settings.yaml."),`
          <div class="settings-row">
            <div>
              <p class="settings-title">Core engine</p>
              <p class="muted">Default is clash-rs (Rust). Mihomo is automatic fallback. Env: CFW_CORE_KIND.</p>
            </div>
            <select data-core-kind class="settings-select">
              <option value="clash_rs" ${(a.coreKind??a.core_kind??"clash_rs")==="clash_rs"?"selected":""}>clash-rs (default, Rust)</option>
              <option value="mihomo" ${(a.coreKind??a.core_kind)==="mihomo"?"selected":""}>mihomo (fallback)</option>
            </select>
          </div>
        `,M("enableIpv6","IPv6","Expose IPv6 option in generated Clash config."),le("Install clash-rs","Apple Silicon only","Download pinned clash-rs v0.10.7 beside mihomo (does not change default).","install-pinned-clash-rs","Install")])}
      ${Mt()}
      ${Lt()}
      ${At()}
      ${N("Paths",[y("Home Directory",o.app_home,"macOS application support root."),y("Settings",o.settings_file,"Clash for Mac shell settings."),y("Profiles",o.profiles_dir,"Imported and generated profile files."),y("Logs",o.logs_dir,"Core, shell and helper logs."),y("Cores",o.cores_dir,"Apple Silicon Clash core binaries."),y("Helpers",o.helpers_dir,"Privileged helper payload staging.")])}
      ${N("macOS",[y("Minimum macOS",e.minimum_macos??"13.0","ARM64-only app baseline."),y("Intel support",e.intel_supported?"Enabled":"Disabled","Removed to optimize Apple Silicon runtime."),y("System proxy",e.system_proxy_strategy??"native manager","Rust SystemConfiguration boundary."),y("Service Mode",b,"Live SMAppService status for the privileged helper."),le("Service Mode",b,"Register the SMAppService helper (approve under Login Items if prompted).","manage-service-mode","Manage")])}
      ${Pt()}
      ${N("Experimental",[M("hideUnavailable","Hide timed-out proxies","Hide nodes that failed latency tests (Timeout)."),y("TUN",e.tun_strategy??"SmAppServiceRootHelper","Production TUN path: SMAppService root helper (not Network Extension)."),y("UI shell","Tauri 2 + WebKit","Native Tauri shell. React is not the product UI."),y("launchd",e.launchd_strategy??"typed launchd contract","No product-layer ad-hoc scripts.")])}
      <section class="panel settings-index">
        <div class="section-heading">
          <div>
            <p class="label">Original Settings Taxonomy</p>
            <h3>CFW Setting Groups</h3>
          </div>
          <span class="badge">${f.length} groups</span>
        </div>
        <div class="settings-taxonomy">
          ${f.map(([h,P])=>`
            <article class="taxonomy-group">
              <h4>${d(h)}</h4>
              ${P.join("")}
            </article>
          `).join("")}
        </div>
      </section>
      ${Dt()}
      <section class="panel deep-link-panel">
        <div class="section-heading">
          <div>
            <p class="label">clash:// protocol</p>
            <h3>Deep link events</h3>
          </div>
          <button class="button ghost" data-action="clear-deep-links">Clear</button>
        </div>
        <pre>${s.deepLinks.length?d(JSON.stringify(s.deepLinks,null,2)):"No deep links received yet."}</pre>
      </section>
    </div>
  `}var It={general:Ie,proxies:ot,profiles:yt,providers:wt,logs:_t,connections:St,rules:Ct,settings:Rt,feedback:Et};function g(){let e=me(s.activePage);document.title="";let t=document.getElementById("product-name");t&&(t.textContent=s.payload.product?.name??"Clash for Mac");let a=document.getElementById("status-title");a&&(a.textContent=`${e.title} - ${s.mode} Mode`),document.getElementById("page-title").textContent=e.title,document.getElementById("page-summary").textContent=e.summary;let o=s.coreStatus?.state==="Running",r=document.getElementById("sidebar-status");r&&(r.textContent=o?"Connected":"Disconnected");let n=document.getElementById("sidebar-status-dot");n&&(n.className=o?"on":""),F(),Xe(),document.getElementById("page").innerHTML=(It[s.activePage]??Ie)(),ze(),_(),s.profileInspector?.mode==="edit"&&s.profileInspector.focusKey&&requestAnimationFrame(()=>Ut(s.profileInspector.focusKey))}function F(){let e=document.getElementById("upload-rate"),t=document.getElementById("download-rate"),a=document.getElementById("runtime-value"),o=document.getElementById("traffic-progress");if(e&&(e.textContent=fe(s.traffic.upload)),t&&(t.textContent=fe(s.traffic.download)),a&&(a.textContent=Se(s.traffic.runtimeSeconds)),o){let r=Math.min(100,Math.max(0,(s.traffic.upload+s.traffic.download)*4));o.style.width=`${r}%`}}function J(){w.renderFrame===null&&(w.renderFrame=window.requestAnimationFrame(()=>{w.renderFrame=null,w.connectionRowEls=null,g()}))}async function ye(e){let t=s.profiles.find(r=>r.id===e);if(!t)throw new Error(`profile not found: ${e}`);if(t.active)return i("info","profile",`${t.name} is already active`),!1;let a=k().active?k().id:null,o=await p("write_settings_snapshot",{settings:{...S(),active_profile:e}});v(o),await $();try{let r=await p("apply_active_profile");return i("info","profile",`Profile switched to ${k().name}; config.yaml updated (${x(r.bytes??0)})`),s.toggles.breakOnProxyChange&&await ee("profile"),!0}catch(r){let n=await p("write_settings_snapshot",{settings:{...S(),active_profile:a}});throw v(n),await $(),i("error","profile",`Could not switch to ${t.name}: ${r.message??String(r)}`),r}}function ze(){document.querySelectorAll("[data-toggle]").forEach(n=>{n.addEventListener("change",async c=>{let l=c.currentTarget.dataset.toggle,u=c.currentTarget.checked;try{await H(l,u,"ui")}catch(f){i("warning","ui",`${l} refused: ${f.message??String(f)}`)}g()})}),document.querySelectorAll("[data-log-level]").forEach(n=>{n.addEventListener("change",async c=>{let l=s.logLevel;s.logLevel=c.currentTarget.value;try{let u=await p("write_settings_snapshot",{settings:S()});v(u);try{await p("set_log_level",{level:s.logLevel}),i("info","settings",`Clash log level applied: ${s.logLevel}`)}catch(f){s.controllerStatus="controller offline",i("warning","settings",`Log level saved; controller apply failed: ${f.message??String(f)}`)}}catch(u){s.logLevel=l,i("error","settings",`Log level refused: ${u.message??String(u)}`)}g()})}),document.querySelectorAll("[data-mixed-port]").forEach(n=>{n.addEventListener("change",()=>{z("save-mixed-port").catch(c=>{i("error","settings",c.message??String(c)),g()})}),n.addEventListener("keydown",c=>{c.key==="Enter"&&c.currentTarget.blur()})}),document.querySelectorAll("[data-random-mixed-port]").forEach(n=>{n.addEventListener("change",async c=>{try{let l=await p("write_settings_snapshot",{settings:{...S(),randomMixedPort:c.currentTarget.checked}});v(l),i("info","settings",`Random mixed-port ${c.currentTarget.checked?"enabled":"disabled"}`)}catch(l){i("error","settings",`Random mixed-port refused: ${l.message??String(l)}`)}g()})}),document.querySelectorAll("[data-core-kind]").forEach(n=>{n.addEventListener("change",async c=>{let l=c.currentTarget.value||"mihomo";try{let u=await p("write_settings_snapshot",{settings:{...S(),coreKind:l,core_kind:l}});v(u),i("info","core",l==="mihomo"?"Preferred core set to mihomo (manual override)":"Preferred core set to clash-rs (default)")}catch(u){i("error","settings",`Core kind refused: ${u.message??String(u)}`)}g()})});let e=document.querySelector("[data-proxy-filter]");e&&e.addEventListener("input",n=>{s.proxyFilter=n.currentTarget.value,g()}),document.querySelectorAll("[data-collapse-group]").forEach(n=>{n.addEventListener("click",c=>{let l=c.currentTarget.dataset.collapseGroup;s.collapsedProxyGroups.has(l)?s.collapsedProxyGroups.delete(l):s.collapsedProxyGroups.add(l),g()})}),document.querySelectorAll("[data-scroll-group]").forEach(n=>{n.addEventListener("click",c=>{let l=c.currentTarget.dataset.scrollGroup;document.getElementById(`proxy-group-${at(l)}`)?.scrollIntoView({block:"start",behavior:"smooth"})})}),document.querySelectorAll("[data-proxy-group-tab]").forEach(n=>{n.addEventListener("click",c=>{pe(),s.activeProxyGroup=c.currentTarget.dataset.proxyGroupTab,g()})});let t=document.querySelector("[data-profile-file]");t&&t.addEventListener("change",()=>{z("import-profile-file").catch(n=>{i("error","profile",n.message??String(n)),g()})}),document.querySelectorAll("[data-page]").forEach(n=>{n.addEventListener("click",async c=>{let l=c.currentTarget.dataset.page;l!=="proxies"&&pe(),s.activePage=l,await p("open_page",{page:l}),g(),l==="rules"&&(await ue(),g())})}),document.querySelectorAll("[data-mode]").forEach(n=>{n.addEventListener("click",async c=>{let l=s.mode;s.mode=c.currentTarget.dataset.mode;try{await p("set_proxy_mode",{mode:s.mode});let u=await p("write_settings_snapshot",{settings:S()});v(u),i("info","mode",`Proxy mode switched to ${s.mode}`),s.toggles.breakOnProxyChange&&await ee("mode")}catch(u){s.mode=l,s.controllerStatus="controller offline",i("warning","mode",`Proxy mode refused by controller: ${u.message??String(u)}`)}g()})}),document.querySelectorAll("[data-group][data-node]").forEach(n=>{n.addEventListener("click",async c=>{let l=s.proxyGroups.find(f=>f.name===c.currentTarget.dataset.group);if(!l)return;let u=l.now;l.now=c.currentTarget.dataset.node;try{await p("select_proxy",{group:l.name,proxy:l.now}),i("info","proxy",`Proxy group ${l.name} switched to ${l.now}`),s.toggles.breakOnProxyChange&&await ee(l.name)}catch(f){l.now=u,s.controllerStatus="controller offline",i("warning","proxy",`Proxy selection refused: ${f.message??String(f)}`)}g()})}),document.querySelectorAll("[data-profile]").forEach(n=>{n.addEventListener("click",async c=>{c.preventDefault(),c.stopPropagation();let l=c.currentTarget.dataset.profile;try{await ye(l)}catch(u){i("error","profile",`Profile switch failed: ${u.message??String(u)}`)}g()})}),document.querySelectorAll("[data-update-profile]").forEach(n=>{n.addEventListener("click",async c=>{let l=s.profiles.find(f=>f.id===c.currentTarget.dataset.updateProfile);if(!l)return;if(!l.sourceUrl){i("warning","profile",`${l.name} is a local profile; use Import File again to replace it`),g();return}let u=l.active;try{let f=await p("update_profile",{id:l.id});await $(),u&&await p("apply_active_profile"),i("info","profile",`${f.name} subscription updated${u?" and config.yaml reapplied":""}`)}catch(f){i("error","profile",`Update failed for ${l.name}: ${f.message??String(f)}`)}g()})}),document.querySelectorAll("[data-reveal-profile]").forEach(n=>{n.addEventListener("click",async c=>{let l=c.currentTarget.dataset.revealProfile;try{await p("reveal_profile",{id:l}),i("info","profile",`Profile revealed in Finder: ${l}`)}catch(u){i("warning","profile",`Show in Finder failed: ${u.message??String(u)}`)}g()})}),document.querySelectorAll("[data-delete-profile]").forEach(n=>{n.addEventListener("click",async c=>{let l=c.currentTarget.dataset.deleteProfile;try{await Ne("delete",l)}catch(u){i("error","profile",`Delete failed: ${u.message??String(u)}`)}g()})}),document.querySelectorAll("[data-profile-card]").forEach(n=>{n.addEventListener("click",async c=>{if(c.target.closest("button, a, input, textarea, select"))return;let l=n.dataset.profileCard;if(l){try{await ye(l)}catch{}g()}}),n.addEventListener("contextmenu",c=>{c.preventDefault(),c.stopPropagation(),ht(n.dataset.profileCard,c.clientX,c.clientY)})}),document.querySelectorAll("[data-profile-action]").forEach(n=>{n.addEventListener("click",async c=>{let l=c.currentTarget.dataset.profileAction,u=c.currentTarget.dataset.profileId;try{await I(u,l),i("info","profile",`${l} opened for ${u}`)}catch(f){i("error","profile",`${l} failed for ${u}: ${f.message??String(f)}`)}g()})}),document.querySelectorAll("[data-provider-update], [data-rule-provider-update]").forEach(n=>{n.addEventListener("click",async c=>{let l=c.currentTarget.dataset.providerUpdate,u=c.currentTarget.dataset.ruleProviderUpdate,f=l??u,b=G(l?"proxy-update":"rule-update",f);s.providerActions.add(b),g();try{l?await p("update_proxy_provider",{name:l}):await p("update_rule_provider",{name:u}),await Y(),i("info","provider",`${f} update requested through Clash controller`)}catch(h){s.controllerStatus="controller offline",i("warning","provider",`${f} update failed: ${h.message??String(h)}`)}finally{s.providerActions.delete(b)}g()})}),document.querySelectorAll("[data-provider-health]").forEach(n=>{n.addEventListener("click",async c=>{let l=c.currentTarget.dataset.providerHealth,u=G("proxy-health",l);s.providerActions.add(u),g();try{await p("health_check_proxy_provider",{name:l}),await Y(),i("info","provider",`${l} health check requested through Clash controller`)}catch(f){s.controllerStatus="controller offline",i("warning","provider",`${l} health check failed: ${f.message??String(f)}`)}finally{s.providerActions.delete(u)}g()})}),document.querySelectorAll("[data-log-filter]").forEach(n=>{n.addEventListener("click",c=>{s.logFilter=c.currentTarget.dataset.logFilter,g()})});let a=document.querySelector("[data-log-search]");a&&a.addEventListener("input",n=>{s.logSearch=n.currentTarget.value,g()});let o=document.querySelector("[data-connection-search]");o&&o.addEventListener("input",n=>{s.connectionSearch=n.currentTarget.value,g()});let r=document.querySelector("[data-rule-search]");r&&r.addEventListener("input",n=>{s.ruleSearch=n.currentTarget.value,g()}),document.querySelectorAll("[data-connection-sort]").forEach(n=>{n.addEventListener("click",c=>{let l=c.currentTarget.dataset.connectionSort;s.connectionSort===l?s.connectionSortDesc=!s.connectionSortDesc:(s.connectionSort=l,s.connectionSortDesc=!1),g()})}),document.querySelectorAll("[data-connection-detail]").forEach(n=>{n.addEventListener("click",c=>{s.connectionDetailId=c.currentTarget.dataset.connectionDetail,g()})}),document.querySelectorAll("[data-modal-stop]").forEach(n=>{n.addEventListener("click",c=>c.stopPropagation())}),document.querySelectorAll("[data-copy-text]").forEach(n=>{n.addEventListener("click",async c=>{let l=c.currentTarget.dataset.copyText??"";try{await navigator.clipboard.writeText(l),i("info","clipboard","Connection field copied")}catch{i("warning","clipboard","Clipboard API refused copy")}g()})}),document.querySelectorAll("[data-connection-facet]").forEach(n=>{n.addEventListener("click",c=>{s.connectionSearch=c.currentTarget.dataset.connectionFacet,g()})}),document.querySelectorAll("[data-close-connection]").forEach(n=>{n.addEventListener("click",async c=>{let l=c.currentTarget.dataset.closeConnection;s.closingConnectionIds.add(l),g();try{await p("close_connection",{id:l}),await W(),i("info","connection",`Connection ${l} closed`)}catch(u){s.controllerStatus="controller offline",i("warning","connection",`Controller close failed for ${l}: ${u.message??String(u)}`)}finally{s.closingConnectionIds.delete(l)}g()})})}function qt(){w.globalEventsBound||(w.globalEventsBound=!0,document.addEventListener("keydown",e=>{e.key==="Escape"&&(s.profileContextMenu||s.glassDialog)&&(e.preventDefault(),L())}),document.addEventListener("click",e=>{let a=(e.target instanceof Element?e.target:e.target?.parentElement)?.closest("[data-action]");a&&(e.preventDefault(),e.stopPropagation(),z(a.dataset.action).catch(o=>{i("error","ui",o.message??String(o)),g()}))}),document.addEventListener("keydown",e=>{let t=e.key.toLowerCase();if(!(e.metaKey||e.ctrlKey)||e.altKey)return;let o=e.target,r=o instanceof HTMLInputElement||o instanceof HTMLTextAreaElement||o instanceof HTMLSelectElement||o?.isContentEditable,n={1:"general",2:"proxies",3:"profiles",4:"logs",5:"connections",6:"settings"};if(!r&&n[t]){e.preventDefault(),s.activePage=n[t],i("info","shortcut",`Opened ${me(s.activePage).title}`),g();return}if(r)return;let c={g:()=>de("mode:Global"),r:()=>de("mode:Rule"),d:()=>de("mode:Direct"),p:()=>H("systemProxy",!s.toggles.systemProxy,"shortcut"),t:()=>H("tunMode",!s.toggles.tunMode,"shortcut"),m:()=>H("mixin",!s.toggles.mixin,"shortcut"),s:()=>z("save-settings")}[t];c&&(e.preventDefault(),c().catch(l=>{i("warning","shortcut",l.message??String(l)),g()}))}))}async function H(e,t,a){let o=s.toggles[e];s.toggles[e]=t;try{if(e==="systemProxy"){let r=await p("set_system_proxy_enabled",{enabled:t});v(r),await te()}else if(e==="tunMode"){if(t&&s.serviceModeStatus!=="Enabled"){s.toggles[e]=o,s.glassDialog={kind:"info",payload:{title:"TUN Mode",body:"To enable this mode, please install Service Mode first!"}},_();return}let r=await p("set_tun_enabled",{enabled:t});v(r)}else if(e==="mixin"){let r=await p("write_settings_snapshot",{settings:{...S(),mixin:t}});if(v(r),k().active){let n=await p("apply_active_profile");i("info",a,`Mixin ${t?"enabled":"disabled"}; active config reapplied (${x(n.bytes??0)})`)}}else if(e==="startAtLogin"){let r=await p("set_launch_at_login_enabled",{enabled:t});v(r)}else if(e==="allowLan"){let r=await p("set_allow_lan",{enabled:t});v(r)}else if(e==="enableIpv6"){let r=await p("set_ipv6",{enabled:t});v(r)}else{let r=await p("write_settings_snapshot",{settings:S()});if(v(r),e==="usePacScript"&&s.toggles.systemProxy){let n=await p("set_system_proxy_enabled",{enabled:!0});v(n),await te()}}i("info",a,`${e} changed to ${t?"on":"off"}`)}catch(r){if(s.toggles[e]=o,e==="tunMode")try{await ae()}catch{}throw r}}async function z(e){if(e==="open-settings"&&(s.activePage="settings"),e==="scroll-to-selected-proxy"){let a=(s.proxyGroups.find(o=>o.name===s.activeProxyGroup)??s.proxyGroups[0])?.now;if(!a){i("warning","proxy","No selected proxy to scroll to");return}s.toggles.showProxiesList=!0,s.proxyBlinkNode=a,g(),requestAnimationFrame(()=>{document.querySelector(`[data-proxy-node="${CSS.escape(a)}"]`)?.scrollIntoView({block:"center",behavior:"smooth"})}),setTimeout(()=>{s.proxyBlinkNode===a&&(s.proxyBlinkNode=null,s.activePage==="proxies"&&g())},1200)}if((e==="toggle-hide-timed-out"||e==="toggle-hide-unavailable")&&(s.toggles.hideUnavailable=!s.toggles.hideUnavailable),e==="toggle-show-proxies"&&(s.toggles.showProxiesList=s.toggles.showProxiesList===!1),e==="toggle-proxy-filter"&&(s.toggles.showProxyFilter=!s.toggles.showProxyFilter,s.toggles.showProxyFilter||(s.proxyFilter="")),e==="break-proxy-connections"){let t=s.connections.length;try{await p("close_all_connections"),i("warning","proxy",`Broke ${t} connection(s)`),await W()}catch(a){i("warning","proxy",`Break connections failed: ${a.message??String(a)}`)}}if(e==="open-providers"&&(s.activePage="providers"),e==="open-rules"&&(s.activePage="rules",await ue()),e==="close-all"){let t=s.connections.length;s.closingAllConnections=!0,g();try{await p("close_all_connections"),i("warning","connection",`Closed ${t} active connections`),await W()}catch(a){s.controllerStatus="controller offline",i("warning","connection",`Controller close-all failed; keeping local rows: ${a.message??String(a)}`)}finally{s.closingAllConnections=!1}}if(e==="delay-test"){if(s.toggles.testingDelays){pe(),i("info","proxy","Delay test cancelled"),V();return}let t=s.proxyGroups.find(o=>o.name===s.activeProxyGroup)??s.proxyGroups.find(o=>X(o.type)&&o.name.toUpperCase()!=="GLOBAL")??s.proxyGroups[0]??null,a=tt([...new Set((t?.options??[]).map(o=>o.name))].filter(o=>!["DIRECT","REJECT","REJECT-DROP","PASS","COMPATIBLE"].includes(String(o).toUpperCase())));if(!a.length)i("warning","proxy","No proxy nodes available for delay test");else if(U()?.core?.invoke){let o=w.delayTestGeneration=(w.delayTestGeneration??0)+1;s.toggles.testingDelays=!0,t&&t.options.forEach(r=>{a.includes(r.name)&&(r.delay=null,r.dead=!1)}),V(a);try{let r=s.settingsSnapshot?.settings?.delayTestUrl??s.settingsSnapshot?.settings?.delay_test_url??null,n=new Map,c=0;for(;c<a.length&&o===w.delayTestGeneration;){let l=Me(),u=a.slice(c,c+l);c+=u.length;let f=await p("test_proxy_delays",{proxies:u,url:r,timeout_ms:5e3,timeoutMs:5e3,concurrency:l});if(o!==w.delayTestGeneration)break;let b=new Set;for(let h of f??[])b.add(h.name),Number.isFinite(h.delay)&&h.delay>0?(n.set(h.name,h.delay),ce(h.name,h.delay)):(n.set(h.name,0),ce(h.name,0));for(let h of u)!b.has(h)&&!n.has(h)&&(n.set(h,0),ce(h,0));V(u)}if(o===w.delayTestGeneration){Le(a);let l=[...n.values()].filter(f=>f<=0).length+a.filter(f=>!n.has(f)).length,u=[...n.values()].filter(f=>f>0).length;i(l?"warning":"info","proxy",`Delay test (${t?.name??"group"}): ${u} ok${l?`, ${l} timed out`:""} \xB7 concurrency ${Me()}`)}}catch(r){(w.delayTestGeneration??0)===o&&(Le(a),i("warning","proxy",`Delay test failed: ${r.message??String(r)}`))}finally{(w.delayTestGeneration??0)===o&&(s.toggles.testingDelays=!1,V(a))}}else s.proxyGroups.forEach(o=>{o.options.forEach((r,n)=>{r.delay>0&&(r.delay=Math.max(18,r.delay+(n%2===0?-5:7)))})}),i("info","proxy","Delay test completed in preview mode")}if(e==="reload-proxies"){let t=await W();i(t?"info":"warning","proxy",t?"Controller snapshot reloaded":"Controller unavailable; keeping local data")}if(e==="start-core")try{s.coreStatus=await p("start_core"),s.coreStatus?.state==="Running"&&(s.coreStartedAt=Date.now(),s.traffic.runtimeSeconds=0,F()),i("info","core",s.coreStatus.message),await W()}catch(t){s.coreStatus=await p("core_status"),i("error","core",t.message??String(t))}if(e==="install-pinned-core"||e==="install-latest-core")try{i("info","core","Installing pinned darwin-arm64 Mihomo core package...");let t=await p("install_pinned_mihomo_core");s.coreStatus=await p("core_status"),i("info","core",`Pinned core installed: ${x(t.bytes??0)} \xB7 ${String(t.sha256??"").slice(0,12)}`)}catch(t){i("error","core",`Core install failed: ${t.message??String(t)}`)}if(e==="install-pinned-clash-rs")try{i("info","core","Installing pinned clash-rs aarch64 (does not change default core)...");let t=await p("install_pinned_clash_rs_core");i("info","core",`Pinned clash-rs installed: ${x(t.bytes??0)} \xB7 ${String(t.sha256??"").slice(0,12)}`)}catch(t){i("error","core",`clash-rs install failed: ${t.message??String(t)}`)}if(e==="stop-core")try{s.coreStatus=await p("stop_core"),s.coreStartedAt=null,s.traffic.runtimeSeconds=0,F(),i("warning","core",s.coreStatus.message)}catch(t){i("error","core",t.message??String(t))}if(e==="copy-proxy-exports"){let t=s.settingsSnapshot?.settings?.mixed_port??7890,a=[`export https_proxy=http://127.0.0.1:${t}`,`export http_proxy=http://127.0.0.1:${t}`,`export all_proxy=socks5://127.0.0.1:${t}`].join(`
`);try{await navigator.clipboard.writeText(a),i("info","shell","Copied proxy export commands for Terminal")}catch(o){i("warning","clipboard",o.message??String(o))}}if(e==="toggle-random-mixed-port"){let t=!!(s.settingsSnapshot?.settings?.randomMixedPort??s.settingsSnapshot?.settings?.random_mixed_port);try{let a=await p("write_settings_snapshot",{settings:{...S(),randomMixedPort:!t,random_mixed_port:!t}});v(a),i("info","settings",`Random mixed-port ${t?"disabled":"enabled"}`)}catch(a){i("warning","settings",a.message??String(a))}}if(e==="allow-lan-info"){s.glassDialog={kind:"info",payload:{title:"Allow LAN",body:"Turn on to listen on all interfaces by default, or else only listen on 127.0.0.1. You can change the Bind Address on the right to specify a particular interface."}},_();return}if(e==="show-network-interfaces")try{let t=await p("network_diagnostics");s.networkDiagnostics=t,s.glassDialog={kind:"network-interfaces",payload:t?.services??[],defaultRoute:t?.default_route_interface??t?.defaultRouteInterface??"unknown"},_();return}catch(t){i("warning","network",t.message??String(t))}if(e==="edit-bind-address"){let t=s.settingsSnapshot?.settings??{};s.glassDialog={kind:"bind-address",payload:Re(t)},_();return}if(e==="preview-runtime-config")try{let t=await p("read_runtime_config_text");s.glassDialog={kind:"preview-config",payload:t},_();return}catch(t){i("warning","core",`Config preview failed: ${t.message??String(t)}`)}if(e==="dns-query"){s.glassDialog={kind:"dns-query",payload:{name:"www.gstatic.com",type:"A",result:""}},_();return}if(e==="script-test"){s.glassDialog={kind:"script-test"},_();return}if(e==="open-controller-dashboard"){let t=s.settingsSnapshot?.settings??{},a=t.external_controller_host??"127.0.0.1",o=t.external_controller_port??9090,r=t.secret?encodeURIComponent(t.secret):"",n=`https://clash.razord.top/#/?host=${encodeURIComponent(a)}&port=${o}${r?`&secret=${r}`:""}`;try{await p("open_external_url",{url:n}),i("info","core",`Opened controller dashboard (${a}:${o})`)}catch(c){try{await navigator.clipboard.writeText(n),i("warning","core",`Open failed; URL copied instead: ${c.message??String(c)}`)}catch(l){i("info","core",n),i("warning","core",c.message??String(c)),i("warning","clipboard",l.message??String(l))}}return}if(e==="tun-info"){s.glassDialog={kind:"info",payload:{title:"TUN Mode",body:"To enable this mode, please install Service Mode first!"}},_();return}if(e==="tun-settings"){let t=s.settingsSnapshot?.settings??{};s.glassDialog={kind:"tun-settings",payload:{stack:t["tun-stack"]??t.tunStack??"mixed",autoRoute:t["tun-auto-route"]??t.tunAutoRoute??!0,strictRoute:t["tun-strict-route"]??t.tunStrictRoute??!0,dnsHijack:t["tun-dns-hijack"]??t.tunDnsHijack??`any:53
[::]:53`}},_();return}if(e==="tun-reset-dns"){let t=s.settingsSnapshot?.settings??{};s.glassDialog={kind:"tun-reset-dns",payload:t["restore-dns-servers"]??t.restoreDnsServers??"Empty"},_();return}if(e==="mixin-info"){s.glassDialog={kind:"info",payload:{title:"Mixin",body:"When Mixin is enabled, YAML is recursively merged into the generated config.yaml before the core reloads."}},_();return}if(e==="edit-mixin"){let t=s.settingsSnapshot?.settings??{};s.glassDialog={kind:"edit-mixin",payload:t.mixin_yaml??t.mixinYaml??s.mixinYaml??""},_();return}if(e==="open-home-directory")try{await p("reveal_home_directory"),i("info","shell","Home Directory opened in Finder")}catch(t){i("warning","shell",`Open Folder failed: ${t.message??String(t)}`)}if(e==="save-mixed-port"){let t=document.querySelector("[data-mixed-port]"),a=Number.parseInt(t?.value??"",10);if(!Number.isInteger(a)||a<1||a>65535)i("error","settings","mixed-port must be between 1 and 65535");else{let o=s.settingsSnapshot?.settings?.mixed_port??m.settings.mixed_port;try{let r=await p("write_settings_snapshot",{settings:{...S(),mixed_port:a}});if(v(r),k().active&&await p("apply_active_profile"),s.toggles.systemProxy){let n=await p("set_system_proxy_enabled",{enabled:!0});v(n)}i("info","settings",`mixed-port saved: ${a}${s.coreStatus?.state==="Running"?"; restart core to guarantee full reload":""}`)}catch(r){let n=await p("write_settings_snapshot",{settings:{...S(),mixed_port:o}});v(n),i("error","settings",`mixed-port refused: ${r.message??String(r)}`)}}}if(e==="import-profile"){let a=document.querySelector("[data-profile-url]")?.value?.trim();if(!a)i("warning","profile","Profile URL is required before download");else{let o=k().active?k().id:null,r=await p("import_profile_url",{url:a,name:null,activate:!0});await $();try{let n=await p("apply_active_profile");i("info","profile",`Remote profile imported and applied: ${r.name} (${x(n.bytes??r.bytes??0)})`)}catch(n){let c=await p("write_settings_snapshot",{settings:{...S(),active_profile:o}});v(c),await $(),i("error","profile",`Remote profile imported, but config apply failed: ${n.message??String(n)}`)}}}if(e==="paste-profile-url"){let t=document.querySelector("[data-profile-url]");try{let a=await navigator.clipboard.readText();t&&(t.value=a.trim()),i("info","profile","Profile URL pasted from clipboard")}catch{i("warning","profile","Clipboard read was refused")}}if(e==="import-profile-file"){let t=document.querySelector("[data-profile-file]"),a=t?.files?.[0];if(a){let o=k().active?k().id:null,r=await a.text(),n=await p("import_profile_text",{name:a.name,body:r,activate:!0});await $();try{let c=await p("apply_active_profile");i("info","profile",`Local profile imported and applied: ${n.name} (${x(c.bytes??n.bytes??0)})`)}catch(c){let l=await p("write_settings_snapshot",{settings:{...S(),active_profile:o}});v(l),await $(),i("error","profile",`Local profile imported, but config apply failed: ${c.message??String(c)}`)}finally{t&&(t.value="")}}else{t?.click();return}}if(e==="migrate-legacy-profiles"){let t=await p("migrate_legacy_cfw_profiles");if(await $(),k().active)try{let a=await p("apply_active_profile");i("info","profile",`Migrated ${t.length} CFW profile(s); active config applied (${x(a.bytes??0)})`)}catch(a){i("warning","profile",`Migrated ${t.length} CFW profile(s), but active config apply failed: ${a.message??String(a)}`)}else i("info","profile",`Migrated ${t.length} CFW profile(s)`)}if(e==="update-all-profiles"){let t=s.profiles.filter(r=>r.sourceUrl),a=0,o=0;for(let r of t)try{await p("update_profile",{id:r.id}),a+=1}catch(n){o+=1,i("warning","profile",`Update failed for ${r.name}: ${n.message??String(n)}`)}if(await $(),k().active)try{await p("apply_active_profile")}catch(r){i("warning","profile",`Active profile reapply failed: ${r.message??String(r)}`)}i(o?"warning":"info","profile",`Update All profiles completed: ${a} updated${o?`, ${o} failed`:""}`)}if(e==="save-profile-editor"){let t=document.querySelector("[data-profile-editor]"),a=s.profileInspector;if(!t||!a?.profile?.id)i("warning","profile","No profile editor is open");else{let o=await p("save_profile_text",{id:a.profile.id,body:t.value});o.active&&await p("apply_active_profile"),await $(),await I(o.id,"edit"),i("info","profile",`Profile YAML saved${o.active?" and active config hot-reloaded":""}: ${x(o.bytes??0)}`)}}if(e==="close-profile-inspector"&&(s.profileInspector=null),e==="update-all-providers"){s.providerBulkActions.add(e),g();try{let[t,a]=await Promise.allSettled([p("update_all_proxy_providers"),p("update_all_rule_providers")]),o=t.status==="fulfilled"?t.value:O("update-proxy"),r=a.status==="fulfilled"?a.value:O("update-rule");t.status==="rejected"&&i("warning","provider",`Proxy provider list failed: ${t.reason?.message??String(t.reason)}`),a.status==="rejected"&&i("warning","provider",`Rule provider list failed: ${a.reason?.message??String(a.reason)}`),await Y();let n=oe("Proxy providers",o),c=oe("Rule providers",r),l=re(o)&&re(r)&&t.status==="fulfilled"&&a.status==="fulfilled"?"info":"warning";i(l,"provider",`Update All completed \xB7 ${n} \xB7 ${c}`)}catch(t){s.controllerStatus="controller offline",i("warning","provider",`Update All failed: ${t.message??String(t)}`)}finally{s.providerBulkActions.delete(e),g()}}if(e==="health-check-all"){s.providerBulkActions.add(e),g();try{let t=await p("health_check_all_proxy_providers");await Y(),i(re(t)?"info":"warning","provider",oe("Health Check All",t))}catch(t){s.controllerStatus="controller offline",i("warning","provider",`Health Check All failed: ${t.message??String(t)}`)}finally{s.providerBulkActions.delete(e),g()}}if(e==="flush-fake-ip-cache")try{await p("flush_fake_ip_cache"),i("info","cache","Fake IP cache flushed through Clash controller")}catch(t){s.controllerStatus="controller offline",i("warning","cache",`Fake IP cache flush failed: ${t.message??String(t)}`)}if(e==="reload-rules"){let t=await ue();i(t?"info":"warning","rules",t?`Loaded ${s.rules.length} controller rules`:"Rules controller endpoint unavailable")}if(e==="toggle-log-stream"&&(s.logsPaused=!s.logsPaused,i("info","logs",`Request logs ${s.logsPaused?"paused":"resumed"}`)),e==="clear-logs"&&(s.logs=[]),e==="copy-logs"){let t=s.logs.map(a=>{let o=a.time??a.at??"",r=a.level??"info",n=a.message??a.payload??String(a);return`[${o}] ${r} ${n}`}).join(`
`);try{await navigator.clipboard.writeText(t||"(no logs)"),i("info","logs",`Copied ${s.logs.length} log line(s) to clipboard`)}catch(a){i("warning","logs",`Copy logs refused: ${a.message??String(a)}`)}}if(e==="reveal-logs")try{await p("reveal_logs_directory"),i("info","logs","Logs folder opened in Finder")}catch(t){i("warning","logs",`Open Folder failed: ${t.message??String(t)}`)}if(e==="toggle-connection-stream"&&(s.connectionPaused=!s.connectionPaused,i("info","connections",`Connection view ${s.connectionPaused?"frozen":"unfrozen"}`)),e==="close-connection-detail"&&(s.connectionDetailId=null),e==="clear-connection-search"&&(s.connectionSearch=""),e==="clear-deep-links"&&(s.deepLinks=[]),e==="save-settings"){let t=await p("write_settings_snapshot",{settings:S()});if(v(t),s.toggles.systemProxy){let a=await p("set_system_proxy_enabled",{enabled:!0});v(a),await te()}if(k().active){let a=await p("apply_active_profile");i("info","settings",`cfw-settings.yaml saved; active config reapplied (${x(a.bytes??0)})`)}else i("info","settings","cfw-settings.yaml saved")}if(e==="check-for-updates")try{let t=await p("check_for_updates");if(!t?.available)i("info","updater",`Already up to date (${t?.current??"current"})`);else{let a=t.notes?` \u2014 ${String(t.notes).slice(0,160)}`:"";i("info","updater",`Update ${t.version} available${a}`),window.confirm(`Update to ${t.version} is available. Download and install now?`)&&(i("info","updater",`Installing ${t.version}\u2026`),await p("install_available_update"))}}catch(t){i("warning","updater",`Update check failed: ${t.message??String(t)}`)}if(e==="reload-settings"&&(await ae(),i("info","settings","cfw-settings.yaml reloaded")),e==="manage-service-mode"){s.glassDialog={kind:"service-mode-manage"},_();return}if(e==="update-geoip-database"){if(s.geoipUpdating)return;s.glassDialog={kind:"geoip"},_();return}if(e==="install-helper-service")try{let t=await p("install_helper_service");v(t),i("info","helper","Privileged helper installed through launchd")}catch(t){i("warning","helper",`Helper install needs administrator context: ${t.message??String(t)}`)}if(e==="uninstall-helper-service")try{let t=await p("uninstall_helper_service");v(t),i("info","helper","Privileged helper removed from launchd")}catch(t){i("warning","helper",`Helper uninstall failed: ${t.message??String(t)}`)}if(e==="run-tray-script"){let t=await p("write_settings_snapshot",{settings:S()});v(t);try{let a=await p("run_tray_script"),o=[a.stdout,a.stderr].filter(Boolean).join(" \xB7 ");i(a.status===0?"info":"warning","action",`Tray Script exited ${a.status??"unknown"}${o?` \xB7 ${o}`:""}`)}catch(a){i("warning","action",`Tray Script failed: ${a.message??String(a)}`)}}if(e==="run-child-process"){let t=await p("write_settings_snapshot",{settings:S()});v(t);try{let a=await p("run_child_process"),o=[a.stdout,a.stderr].filter(Boolean).join(" \xB7 ");i(a.status===0?"info":"warning","action",`Child Process exited ${a.status??"unknown"}${o?` \xB7 ${o}`:""}`)}catch(a){i("warning","action",`Child Process failed: ${a.message??String(a)}`)}}if(e==="reset-settings"){s.glassDialog={kind:"reset-settings"},_();return}if(e==="quit-app"){await p("quit_app");return}if(e==="force-quit-app"){await p("force_quit_app");return}g()}async function de(e){if(e?.startsWith("proxy-select:")){let[,t,a]=e.split(":"),o=decodeURIComponent(t??""),r=decodeURIComponent(a??""),n=s.proxyGroups.find(c=>c.name===o);if(n&&r){let c=n.now;n.now=r;try{await p("select_proxy",{group:o,proxy:r}),i("info","tray",`Proxy group ${o} switched to ${r}`),s.toggles.breakOnProxyChange&&await ee(o)}catch(l){n.now=c,i("warning","tray",`Tray proxy selection failed: ${l.message??String(l)}`)}}}if(e?.startsWith("mode:")){let t=e.split(":")[1];if(["Global","Rule","Direct","Script"].includes(t)){let a=s.mode;s.mode=t;try{await p("set_proxy_mode",{mode:t});let o=await p("write_settings_snapshot",{settings:S()});v(o),i("info","tray",`Proxy mode switched to ${t}`),s.toggles.breakOnProxyChange&&await ee("tray mode")}catch(o){s.mode=a,i("warning","tray",`Mode switch failed: ${o.message??String(o)}`)}}}if(e==="toggle-system-proxy"&&await H("systemProxy",!s.toggles.systemProxy,"tray"),e==="toggle-tun-mode"&&await H("tunMode",!s.toggles.tunMode,"tray"),e==="toggle-mixin"&&await H("mixin",!s.toggles.mixin,"tray"),e==="close-all"){await z("close-all");return}if(e==="restart-core"){await z("stop-core"),await z("start-core");return}if(e==="run-tray-script")try{let t=await p("run_tray_script"),a=[t.stdout,t.stderr].filter(Boolean).join(" \xB7 ");i(t.status===0?"info":"warning","tray",`Tray Script exited ${t.status??"unknown"}${a?` \xB7 ${a}`:""}`)}catch(t){i("warning","tray",`Tray Script failed: ${t.message??String(t)}`)}if(e==="toggle-devtools")try{await p("toggle_devtools"),i("info","tray","DevTools toggled")}catch(t){i("warning","tray",t.message??String(t))}e==="move-dashboard"&&(await p("move_dashboard_to_nearest_monitor"),i("info","tray","Dashboard moved to the active monitor")),g()}function i(e,t,a){let o=new Date;s.logs.unshift({time:o.toTimeString().slice(0,8),level:he(e),source:t,message:a,fields:[]}),s.logs=s.logs.slice(0,se)}function Bt(e){let t=(e??[]).map(a=>({time:a.time??"live",level:he(a.level),source:a.source??"core",message:a.message??"",fields:a.fields??[]}));s.logs=[...t.reverse(),...s.logs].slice(0,se)}async function ee(e){let t=s.connections.length;if(t)try{await p("close_all_connections"),s.connections=[],s.connectionStream.rows=new Map,i("warning","connection",`Closed ${t} connection(s) after ${e} switch`)}catch(a){s.controllerStatus="controller offline",i("warning","connection",`Connection cleanup after ${e} switch failed: ${a.message??String(a)}`)}}async function I(e,t,a=null){let o=await p("read_profile_text",{id:e}),r={id:e,mode:t,profile:o,focusKey:a};if(t==="qrcode")try{r.svg=await p("profile_qrcode_svg",{id:e})}catch(n){r.error=n.message??String(n)}s.profileInspector=r}function Ut(e){if(!e)return;let t=document.querySelector("[data-profile-editor]");if(!(t instanceof HTMLTextAreaElement))return;let a=t.value,o=a.match(new RegExp(`^${e}\\s*:`,"im"));if(!o||o.index==null)return;let r=o.index;t.focus(),t.setSelectionRange(r,r+o[0].length);let c=a.slice(0,r).split(`
`).length-1,l=Number.parseFloat(getComputedStyle(t).lineHeight)||18;t.scrollTop=Math.max(0,c*l-40)}async function Nt(){s.payload=await p("boot_payload"),s.lastRefresh="Just now",await ae(),await Oe(),await te(),await Ge(),await $(),g(),Promise.all([je(),Y()]).finally(()=>{i("info","shell","Boot payload reloaded from Rust"),g()})}async function ae(){let e=await p("read_settings_snapshot");v(e)}async function Oe(){try{let e=await p("system_proxy_state");s.toggles.systemProxy=e==="Enabled",e==="External"&&i("info","sysproxy","macOS has a non-Clash proxy configured; Clash for Mac will not overwrite it unless you enable System Proxy here")}catch(e){i("warning","sysproxy",`Unable to read macOS system proxy: ${e.message??String(e)}`)}}async function te(){try{s.networkDiagnostics=await p("network_diagnostics")}catch(e){s.networkDiagnostics=null,i("warning","network",`Unable to inspect macOS network services: ${e.message??String(e)}`)}}async function Ge(){let e=s.coreStatus?.state;try{s.coreStatus=await p("core_status")}catch(a){s.coreStatus=R,i("warning","core",a.message??String(a))}let t=s.coreStatus?.state;t==="Running"?((e!=="Running"||!s.coreStartedAt)&&(s.coreStartedAt=Date.now()),s.traffic.runtimeSeconds=Math.floor((Date.now()-s.coreStartedAt)/1e3)):(s.coreStartedAt=null,s.traffic.runtimeSeconds=0),F();try{s.serviceModeStatus=await p("service_mode_status")}catch{s.serviceModeStatus=null}try{s.geoipStatus=await p("geoip_database_status")}catch(a){s.geoipStatus=null,i("warning","geoip",`Unable to read GeoIP database: ${a.message??String(a)}`)}if(t==="Running")try{s.controllerVersion=await p("controller_version")}catch{s.controllerVersion=null}else s.controllerVersion=null}async function W(){try{let e=await p("controller_snapshot");return e?(We(e),p("refresh_tray_menu").catch(t=>{i("warning","tray",`Tray refresh failed: ${t.message??String(t)}`)}),i("info","controller","Live controller snapshot applied"),!0):(Ae(),s.controllerStatus="reference preview only",!1)}catch(e){return Ae(),s.controllerStatus="controller offline",i("warning","controller",e.message??String(e)),!1}}async function je(e=4,t=600){for(let a=0;a<e;a+=1){if(await W())return!0;a+1<e&&await xe(t)}return!1}function Ae(){U()?.core?.invoke&&(s.proxyGroups=[],s.connections=[],s.rules=[],s.connectionStream.rows=new Map)}async function Y(){try{let e=await p("providers_snapshot");return Ye(e)?(i("info","provider","Live providers snapshot applied"),!0):!1}catch(e){return U()?.core?.invoke&&(s.providers=[],s.ruleProviders=[]),i("warning","provider",e.message??String(e)),!1}}async function ue(){try{let e=await p("rules_snapshot"),t=Array.isArray(e?.rules)?e.rules:[];return s.rules=t.map(a=>({index:String(a.index??""),type:a.kind??a.type??"",payload:a.payload??"",proxy:a.proxy??"",provider:a.provider??"",hits:String(a.extra?.hitCount??a.extra?.hit_count??0),size:a.size??-1,extra:a.extra??{}})),i("info","rules",`Live rules snapshot applied: ${s.rules.length} rules`),!0}catch(e){return U()?.core?.invoke&&(s.rules=[]),i("warning","rules",e.message??String(e)),!1}}async function $(){try{let e=await p("profiles_snapshot");return Array.isArray(e)?(s.profiles=e.map(t=>({id:t.id,name:t.name,type:t.source_url?"Remote":"Local",updated:t.updated_epoch_secs?dt(t.updated_epoch_secs):"unknown",updatedEpochSecs:t.updated_epoch_secs??null,rules:t.rule_count??0,traffic:x(t.bytes??0),active:!!t.active,path:t.path,sourceUrl:t.source_url??null,subscriptionUserinfo:t.subscription_userinfo??null,updateInterval:t.update_interval??null,homeWeb:t.home_web??null})),!0):!1}catch(e){return s.profiles=[],i("warning","profile",e.message??String(e)),!1}}async function Ft(){try{await p("start_connections_stream")}catch(e){i("warning","connections",`Live stream unavailable: ${e.message??String(e)}`)}try{await p("start_log_stream")}catch(e){i("warning","logs",`Log stream unavailable: ${e.message??String(e)}`)}}async function Ht(e){let t=await p("parse_deep_links",{urls:e});for(let a of t??[]){if(a.error){i("warning","protocol",`${a.raw||"clash://"} parse failed: ${a.error}`);continue}let o=a.intent;if(o){if(o.action==="quit"){i("warning","protocol","clash://quit received"),await p("quit_app");continue}if((o.action==="install-config"||o.action==="install-profile")&&o.url)try{let r=k().active?k().id:null,n=await p("import_profile_url",{url:o.url,name:o.name,activate:!0});await $();try{let c=await p("apply_active_profile");i("info","protocol",`${o.action} imported and applied ${n.name} (${x(c.bytes??n.bytes??0)})`)}catch(c){let l=await p("write_settings_snapshot",{settings:{...S(),active_profile:r}});throw v(l),await $(),c}await ae()}catch(r){i("error","protocol",`${o.action} failed: ${r.message??String(r)}`)}else i("warning","protocol",`Unsupported clash:// intent ${o.action}`)}}}async function zt(){qt(),s.payload=await p("boot_payload"),await ae(),await Oe(),await te(),await Ge(),await $(),g(),Promise.all([je(),Y()]).finally(g),document.getElementById("reload-button").addEventListener("click",Nt),await E("cfw://page",e=>{s.activePage=e.payload,g()}),await E("cfw://deep-link",e=>{s.deepLinks=Array.isArray(e.payload)?e.payload:[e.payload],s.deepLinks.length?(i("info","protocol",`Received ${s.deepLinks.length} clash:// URL(s)`),Ht(s.deepLinks).finally(g)):g()}),await E("cfw://tray-action",e=>{de(e.payload).catch(t=>{i("error","tray",t.message??String(t)),g()})}),await E("cfw://network-path",e=>{let t=e.payload?.interface??"unknown";pe(),s.proxyGroups.forEach(a=>{a.options.forEach(o=>{typeof o.delay=="number"&&(o.delay=null,o.dead=!1)})}),s.activePage==="proxies"&&V(),i("info","network",`Default route changed (${t}); delay badges marked stale \u2014 re-run Delay Test`)}),await E("cfw://connections-snapshot",e=>{s.connectionPaused||(Ee(e.payload),F(),s.activePage==="connections"?kt():s.activePage==="general"&&J())}),await E("cfw://core-status",e=>{s.coreStatus=e.payload,F(),s.activePage==="general"&&J()}),await E("cfw://log-lines",e=>{s.logsPaused||(Bt(e.payload),s.activePage==="logs"&&J())}),await E("cfw://stream-error",e=>{let t=e.payload??{};i("warning",t.stream??"stream",t.message??"stream unavailable"),(s.activePage==="logs"||s.activePage==="connections")&&J()}),await E("tauri://drag-drop",async e=>{let t=e.payload?.paths??[],a=t.filter(o=>/\.ya?ml$/i.test(o));if(!a.length){t.length&&i("warning","profile","Drag-drop ignored: only .yaml/.yml profile files are supported");return}for(let o of a)await Ot(o)}),await Ft(),window.setInterval(()=>{s.coreStatus?.state==="Running"?(s.coreStartedAt||(s.coreStartedAt=Date.now()),s.traffic.runtimeSeconds=Math.floor((Date.now()-s.coreStartedAt)/1e3)):(s.coreStartedAt=null,s.traffic.runtimeSeconds=0),F()},1e3)}async function Ot(e){let t=k().active?k().id:null;try{let a=await p("import_profile_file",{path:e,name:null,activate:!0});await $();try{let o=await p("apply_active_profile");i("info","profile",`Dropped profile imported and applied: ${a.name} (${x(o.bytes??a.bytes??0)})`)}catch(o){let r=await p("write_settings_snapshot",{settings:{...S(),active_profile:t}});v(r),await $(),i("error","profile",`Dropped profile imported, but config apply failed: ${o.message??String(o)}`)}J()}catch(a){i("error","profile",`Drag-drop import failed: ${a.message??String(a)}`)}}zt().catch(e=>{document.body.innerHTML=`<pre class="fatal">${d(e.stack??e.message??String(e))}</pre>`});})();
