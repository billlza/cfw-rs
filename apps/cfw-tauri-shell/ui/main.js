(()=>{var T={product:{name:"Clash for Mac",version:"0.3.4",parity_source:"Clash for Windows 0.20.39 macOS arm64 public release artifact"},pages:[{id:"general",title:"General",summary:"Overview, runtime status, mode, system proxy and TUN toggles."},{id:"proxies",title:"Proxies",summary:"Proxy groups, selections, delay indicators and quick switching."},{id:"profiles",title:"Profiles",summary:"Subscription import, update, validation and profile lifecycle."},{id:"providers",title:"Providers",summary:"Proxy providers, rule providers, health checks and update actions."},{id:"logs",title:"Logs",summary:"Core logs, helper logs and filtered runtime diagnostics."},{id:"connections",title:"Connections",summary:"Live connection list, close-all action and traffic visibility."},{id:"rules",title:"Rules",summary:"Rule matching visibility and router/provider diagnostics."},{id:"settings",title:"Settings",summary:"Shell settings, startup, deep link, helper and migration options."},{id:"feedback",title:"Feedback",summary:"About, feedback and migration references from the original app."}],settings:{launch_at_login:!1,random_controller_port:!0,retain_window_bounds:!0,show_tray_proxy_delay_indicator:!0,check_for_updates:!1,only_arm64_macos_supported:!0},platform:{minimum_macos:"13.0",intel_supported:!1,system_proxy_strategy:"objc2 SystemConfiguration SCPreferences with networksetup fallback",helper_strategy:"SMAppService privileged helper (Login Items approval required)",launchd_strategy:"typed launchd contract, no ad-hoc shell scripts in product logic",tun_strategy:"SmAppServiceRootHelper"},quality:{performance:{multiplier_vs_cfw_02039:3,cold_start_p95_ms:700,page_switch_p95_ms:16,proxy_toggle_p95_ms:150,profile_apply_p95_ms:450,max_idle_rss_mb:90,log_ingest_events_per_sec:1e4},stability:{crash_free_session_rate_basis_points:9995,restore_system_proxy_on_exit:!0,rollback_failed_profile_apply:!0,idempotent_helper_install:!0,tun_failure_restores_previous_route:!0,single_instance_deep_link_safe:!0},parity_gates:[]}},y={persisted:!1,paths:{app_home:"~/Library/Application Support/Clash for Mac",settings_file:"~/Library/Application Support/Clash for Mac/cfw-settings.yaml",config_file:"~/Library/Application Support/Clash for Mac/config.yaml",profiles_dir:"~/Library/Application Support/Clash for Mac/profiles",logs_dir:"~/Library/Application Support/Clash for Mac/logs",cores_dir:"~/Library/Application Support/Clash for Mac/cores",helpers_dir:"~/Library/Application Support/Clash for Mac/helpers"},settings:{schema_version:1,runtime_mode:"Rule",active_profile:null,system_proxy:!1,proxy_bypass:[],tun_mode:!1,mixin:!1,mixin_yaml:"",profile_parser_script:"",tray_script:"",child_process_command:"",allow_lan:!1,enable_ipv6:!1,launch_at_login:!1,silent_start:!1,break_connections_on_proxy_change:!0,theme:"light",font_family:"","interface-name":"",mixed_port:7890,external_controller_host:"127.0.0.1",external_controller_port:9090,secret:null,retain_window_bounds:!0,show_tray_proxy_delay_indicator:!0,usePacScript:!1,pacScript:"",randomMixedPort:!1,delayTestUrl:"http://www.gstatic.com/generate_204",coreKind:"clash_rs",core_kind:"clash_rs",only_arm64_macos_supported:!0}},I={state:"MissingBinary",pid:null,message:"Missing ~/Library/Application Support/Clash for Mac/cores/clash-rs",spec:{binary_path:"~/Library/Application Support/Clash for Mac/cores/clash-rs",config_path:"~/Library/Application Support/Clash for Mac/config.yaml",home_dir:"~/Library/Application Support/Clash for Mac",log_file:"~/Library/Application Support/Clash for Mac/logs/clash-core.log",controller_host:"127.0.0.1",controller_port:9090,mixed_port:7890,core_kind:"clash_rs"}},s={payload:T,settingsSnapshot:y,coreStatus:I,networkDiagnostics:null,activePage:"general",mode:"Rule",logLevel:"info",proxyFilter:"",activeProxyGroup:null,collapsedProxyGroups:new Set,logFilter:"all",logSearch:"",logsPaused:!1,connectionSearch:"",ruleSearch:"",mixinYaml:"",pacScript:"",profileParserScript:"",trayScript:"",childProcessCommand:"",connectionSort:"age",connectionSortDesc:!1,connectionPaused:!1,connectionDetailId:null,closingConnectionIds:new Set,closingAllConnections:!1,deepLinks:[],lastRefresh:"Just now",controllerStatus:"reference preview only",toggles:{systemProxy:!1,tunMode:!1,mixin:!1,allowLan:!1,startAtLogin:!1,breakOnProxyChange:!0,silentStart:!1,testingDelays:!1,hideUnavailable:!1,enableIpv6:!1,proxyDelayIndicator:!0,showProxyFilter:!0,showProxiesList:!0,usePacScript:!1,showProcess:!0},proxyBlinkNode:null,traffic:{upload:0,download:0,runtimeSeconds:0,memoryMb:0},coreStartedAt:null,serviceModeStatus:null,geoipStatus:null,geoipUpdating:!1,controllerVersion:null,connectionStream:{at:0,uploadTotal:0,downloadTotal:0,rows:new Map},profiles:[],profileInspector:null,profileContextMenu:null,updateInfo:null,kernelCompare:null,tunRuntime:null,glassDialog:null,proxyGroups:[],logs:[],connections:[],providers:[],ruleProviders:[],rules:[],providerActions:new Set,providerBulkActions:new Set};var Pe=new Set(["general","proxies","profiles","providers","logs","connections","rules","settings","feedback"]),ie=200,Me=500,w={renderFrame:null,connectionsPatchFrame:null,logStreamFrame:null,globalEventsBound:!1,connectionRowEls:null,delayTestGeneration:0};var N=()=>window.__TAURI__,Le=e=>new Promise(t=>window.setTimeout(t,e)),p=async(e,t={})=>{let a=N();if(!a?.core?.invoke){if(e==="boot_payload")return T;if(e==="quit_app"||e==="force_quit_app")return null;if(e==="current_platform_design")return T.platform;if(e==="provision_core_binary")return{installed:!1,source_path:null,target_path:I.spec.binary_path,message:"Bundled core provisioning is unavailable outside Tauri"};if(e==="install_core_from_url"||e==="install_latest_mihomo_core"||e==="install_pinned_mihomo_core")throw new Error("Core installer is unavailable outside the Tauri runtime");if(e==="system_proxy_state")return s.toggles.systemProxy?"Enabled":"Disabled";if(e==="network_diagnostics")return null;if(e==="read_settings_snapshot")return y;if(e==="write_settings_snapshot")return{...y,persisted:!0,settings:t.settings};if(e==="reset_settings_snapshot")return y;if(e==="set_system_proxy_enabled")return{...y,persisted:!0,settings:{...y.settings,system_proxy:t.enabled}};if(e==="set_tun_enabled"){if(t.enabled)throw new Error("TUN runtime is unavailable in browser preview");return{...y,persisted:!0,settings:{...y.settings,tun_mode:t.enabled}}}if(e==="run_tray_script")return{status:0,stdout:"preview tray script",stderr:""};if(e==="run_child_process")return{status:0,stdout:"preview child process",stderr:""};if(e==="toggle_devtools"||e==="move_dashboard_to_nearest_monitor")return null;if(e==="set_mixin_enabled")return{...y,persisted:!0,settings:{...y.settings,mixin:t.enabled}};if(e==="set_launch_at_login_enabled")return{...y,persisted:!0,settings:{...y.settings,launch_at_login:t.enabled}};if(e==="install_helper_service")return{...y,persisted:!0,settings:{...y.settings,service_mode:"installed"}};if(e==="uninstall_helper_service")return{...y,persisted:!0,settings:{...y.settings,service_mode:"not-installed"}};if(e==="controller_snapshot"||e==="providers_snapshot"||e==="rules_snapshot"||e==="update_proxy_provider"||e==="update_rule_provider"||e==="health_check_proxy_provider")return null;if(e==="update_all_proxy_providers")return V("update-proxy");if(e==="update_all_rule_providers")return V("update-rule");if(e==="health_check_all_proxy_providers")return V("health-check-proxy");if(e==="service_mode_status")return"Unknown";if(e==="controller_version")return{version:"preview",meta:!0};if(e==="read_runtime_config_text")return`mixed-port: 7890
`;if(e==="dns_query")return{Status:0,Answer:[]};if(e==="set_bind_address")return{...y,persisted:!0,settings:{...y.settings,"bind-address":t.address}};if(e==="open_login_items_settings")return null;if(e==="apply_restore_dns_servers")return"updated DNS on 0/0 service(s)";if(e==="check_for_updates")return{available:!1,current:"0.3.4"};if(e==="install_available_update")return{installed:!1,reason:"preview"};if(e==="tun_runtime_state")return{tun_mode:!1,service_mode:"Unknown",want_core:!1,managed_core_pid:null,tun_enable:!1,active:!1};if(e==="kernel_compare_report"||e==="disable_service_mode")return null;if(e==="enable_service_mode")return"RequiresApproval";if(e==="disable_service_mode")return null;if(e==="geoip_database_status")return{present:!1,file_name:"geoip.metadb",path:`${y.paths.app_home}/geoip.metadb`,mtime_ms:null,size_bytes:null};if(e==="update_geoip_database"){let o=Date.now();return{status:{present:!0,file_name:"geoip.metadb",path:`${y.paths.app_home}/geoip.metadb`,mtime_ms:o,size_bytes:1024},source_url:"https://example.invalid/geoip.metadb",bytes:1024}}if(e==="refresh_tray_menu"||e==="start_connections_stream"||e==="start_log_stream")return null;if(e==="parse_deep_links")return(t.urls??[]).map(o=>({raw:o,intent:null,error:"parse_deep_links is unavailable outside Tauri"}));if(e==="import_profile_url"){let o=`import-${Date.now()}`;return{id:o,name:t.name??"Imported Profile",path:`${y.paths.profiles_dir}/${o}.yaml`,bytes:0,activated:t.activate}}if(e==="import_profile_text"){let o=`local-${Date.now()}`;return{id:o,name:t.name??"Local Profile",path:`${y.paths.profiles_dir}/${o}.yaml`,bytes:t.body?.length??0,activated:t.activate}}if(e==="update_profile")throw new Error("Profile update is unavailable outside the Tauri runtime");if(e==="read_profile_text")return{id:t.id,name:t.id,path:`${y.paths.profiles_dir}/${t.id}.yaml`,body:`proxies: []
proxy-groups: []
rules: []
`,generated_body:`mixed-port: 7890
proxies: []
proxy-groups: []
rules: []
`,active:!1,source_url:null};if(e==="save_profile_text")return{id:t.id,path:"",bytes:t.body?.length??0,active:!1};if(e==="profile_qrcode_svg")throw new Error("Profile QRCode is unavailable outside the Tauri runtime");if(e==="profiles_snapshot")return[];if(e==="delete_profile")return!0;if(e==="reveal_profile"||e==="open_profile_externally"||e==="open_external_url"||e==="update_profile_info"||e==="reveal_home_directory"||e==="reveal_logs_directory")return null;if(e==="apply_active_profile")throw new Error("Profile apply is unavailable outside the Tauri runtime");return e==="reapply_runtime_config"?"/tmp/config.yaml":e==="set_proxy_mode"?null:e==="set_allow_lan"?{...y,persisted:!0,settings:{...y.settings,allow_lan:t.enabled}}:e==="set_ipv6"?{...y,persisted:!0,settings:{...y.settings,enable_ipv6:t.enabled}}:e==="set_log_level"||e==="select_proxy"?null:e==="test_proxy_delays"?[]:e==="close_connection"||e==="close_all_connections"||e==="flush_fake_ip_cache"?null:e==="core_status"?I:e==="start_core"?I:e==="stop_core"?{...I,state:"Stopped",message:"Core stopped"}:null}return a.core.invoke(e,t)},M=async(e,t)=>{let a=N();return a?.event?.listen?a.event.listen(e,t):()=>{}};function c(e){return String(e).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;")}function Ae(e){let t=Math.max(0,Math.floor(Number(e)||0)),a=Math.floor(t/3600).toString().padStart(2,"0"),o=Math.floor(t%3600/60).toString().padStart(2,"0"),r=Math.floor(t%60).toString().padStart(2,"0");return`${a} : ${o} : ${r}`}function ee(e){switch(e){case"Enabled":return"Enabled";case"RequiresApproval":return"Needs Approval";case"NotRegistered":case"NotFound":return"Not Installed";default:return"Unknown"}}function Ee(e){return e!=="Enabled"}function Te(e,t,a=null){return t!=="Enabled"&&!a?.active?"Service Mode required":a?.active?"On":e&&a&&!a.active?"Starting\u2026":t==="Enabled"?"Off":"Service Mode required"}function De(e,t){if(t)return"Updating\u2026";if(!e)return"Loading\u2026";if(!e.present)return"Missing";if(e.mtime_ms==null)return e.file_name||"Present";let a=new Date(e.mtime_ms);if(Number.isNaN(a.getTime()))return e.file_name||"Present";let o=r=>String(r).padStart(2,"0");return`${a.getFullYear()}-${o(a.getMonth()+1)}-${o(a.getDate())} ${o(a.getHours())}:${o(a.getMinutes())}`}function S(e){if(!Number.isFinite(e)||e<=0)return"0 B";let t=["B","KB","MB","GB"],a=e,o=0;for(;a>=1024&&o<t.length-1;)a/=1024,o+=1;return`${a>=10||o===0?a.toFixed(0):a.toFixed(1)} ${t[o]}`}function _e(e){let t=e*1024;return t<1024?`${t.toFixed(t<10?2:0)} KB/s`:`${e.toFixed(1)} MB/s`}function V(e){return{action:e,requested:0,succeeded:[],failed:[]}}function W(e,t){return`${e}:${t}`}function le(e,t){let a=Number(t?.requested??0),o=t?.succeeded?.length??0,r=t?.failed?.length??0,n=(t?.failed??[]).slice(0,3).map(l=>`${l.name}: ${l.error}`).join("; ");return`${e}: ${o}/${a} succeeded${r?`, ${r} failed${n?` (${n})`:""}`:""}`}function ce(e){return(e?.failed?.length??0)===0}function Re(e=[]){let t=e.at(-1);return Number.isFinite(t?.delay)?t.delay:null}function de(e){let t=String(e??"info").toLowerCase();return["warn","wrn","warning"].includes(t)?"warning":["err","error","fatal","ftl"].includes(t)?"error":["debug","dbg","trace","trc"].includes(t)?"debug":"info"}function pe(e){if(!e)return null;try{return new RegExp(e,"i")}catch{return null}}function Se(e){return s.payload.pages.find(t=>t.id===e)??s.payload.pages[0]}function P(){return s.profiles.find(e=>e.active)??s.profiles[0]??{id:"none",name:"No Profile",type:"Local",updated:"never",rules:0,traffic:"0 B",active:!1}}function v(e){if(!e?.settings)return;s.settingsSnapshot=e;let t=e.settings;s.mode=t.runtime_mode??s.mode,s.logLevel=t.logLevel??t["log-level"]??s.logLevel,s.toggles.systemProxy=!!t.system_proxy,s.toggles.tunMode=!!t.tun_mode,s.toggles.mixin=!!t.mixin,s.mixinYaml=t.mixin_yaml??t.mixinYaml??"",s.profileParserScript=t.profile_parser_script??t.profileParserScript??"",s.trayScript=t.tray_script??t.trayScript??"",s.childProcessCommand=t.child_process_command??t.childProcessCommand??"",s.toggles.allowLan=!!t.allow_lan,s.toggles.enableIpv6=!!t.enable_ipv6,s.toggles.startAtLogin=!!t.launch_at_login,s.toggles.silentStart=!!t.silent_start,s.toggles.breakOnProxyChange=!!t.break_connections_on_proxy_change,s.toggles.proxyDelayIndicator=!!t.show_tray_proxy_delay_indicator,s.toggles.usePacScript=!!(t.usePacScript??t.use_pac_script),s.pacScript=t.pacScript??t.pac_script??s.pacScript??"",at(t)}function x(){let e=s.settingsSnapshot?.settings??y.settings;return{...e,runtime_mode:s.mode,logLevel:s.logLevel,system_proxy:s.toggles.systemProxy,proxy_bypass:(document.querySelector("[data-proxy-bypass]")?.value??(s.settingsSnapshot?.settings?.proxy_bypass??[]).join(`
`)).split(/[\n,]+/).map(t=>t.trim()).filter(Boolean),tun_mode:s.toggles.tunMode,mixin:s.toggles.mixin,mixin_yaml:document.querySelector("[data-mixin-yaml]")?.value??s.mixinYaml??e.mixin_yaml??"",profile_parser_script:document.querySelector("[data-profile-parser-script]")?.value??s.profileParserScript??e.profile_parser_script??"",tray_script:document.querySelector("[data-tray-script]")?.value?.trim()??s.trayScript??e.tray_script??"",child_process_command:document.querySelector("[data-child-process-command]")?.value?.trim()??s.childProcessCommand??e.child_process_command??"",allow_lan:s.toggles.allowLan,enable_ipv6:s.toggles.enableIpv6,launch_at_login:s.toggles.startAtLogin,silent_start:s.toggles.silentStart,break_connections_on_proxy_change:s.toggles.breakOnProxyChange,show_tray_proxy_delay_indicator:s.toggles.proxyDelayIndicator,usePacScript:s.toggles.usePacScript,pacScript:document.querySelector("[data-pac-script]")?.value??s.pacScript??e.pacScript??e.pac_script??"",theme:document.querySelector("[data-theme-setting]")?.value??e.theme??"light",font_family:document.querySelector("[data-font-family]")?.value?.trim()??e.font_family??"","interface-name":document.querySelector("[data-outbound-interface]")?.value?.trim()??e["interface-name"]??e.interfaceName??"",randomMixedPort:document.querySelector("[data-random-mixed-port]")?.checked??!!(e.randomMixedPort??e.random_mixed_port),delayTestUrl:document.querySelector("[data-delay-test-url]")?.value?.trim()||e.delayTestUrl||e.delay_test_url||"http://www.gstatic.com/generate_204",coreKind:document.querySelector("[data-core-kind]")?.value||e.coreKind||e.core_kind||"clash_rs",core_kind:document.querySelector("[data-core-kind]")?.value||e.coreKind||e.core_kind||"clash_rs"}}function at(e){let t=e.theme==="dark"?"dark":"light";document.documentElement.dataset.theme=t;let a=String(e.font_family??e.fontFamily??"").trim();document.documentElement.style.setProperty("--sans",a?`"${a}", "Avenir Next", "SF Pro Text", "Helvetica Neue", sans-serif`:'"Avenir Next", "SF Pro Text", "Helvetica Neue", sans-serif')}function st(e){if(!e)return;let t=e.config??{},a=t.mode?t.mode[0].toUpperCase()+t.mode.slice(1).toLowerCase():null;["Global","Rule","Direct","Script"].includes(a)&&(s.mode=a);let o=t["allow-lan"]??t.allow_lan,r=t["mixed-port"]??t.mixed_port;typeof o=="boolean"&&(s.toggles.allowLan=o),typeof t.ipv6=="boolean"&&(s.toggles.enableIpv6=t.ipv6),(t["log-level"]||t.log_level)&&(s.logLevel=t["log-level"]??t.log_level),typeof r=="number"&&(s.settingsSnapshot.settings.mixed_port=r);let n=new Map((e.proxies?.proxies??[]).map(g=>[g.name,g])),l=e.proxies?.groups??[],d=new Map(l.map(g=>[g.name,g])),u=new Map;s.toggles.testingDelays&&s.proxyGroups.forEach(g=>{g.options.forEach(f=>{u.set(f.name,f.delay)})}),s.proxyGroups=l.map(g=>({name:g.name,type:g.kind,now:g.now??g.options?.[0]??"DIRECT",options:(g.options??[]).map(f=>{let m=n.get(f),C=d.get(f),$=Re(m?.history??C?.history??[]);return s.toggles.testingDelays&&u.has(f)&&($=u.get(f)),{name:f,delay:$,dead:!1,kind:m?.kind??m?.type??C?.kind??g.kind??"Proxy",udp:m?.udp??null}})})),Ne(e.connections),s.controllerStatus="controller live"}function Ne(e){if(!e)return;let t=Date.now(),a=s.connectionStream.at?Math.max(.25,(t-s.connectionStream.at)/1e3):0,o=e.upload??e.uploadTotal??e.upload_total??0,r=e.download??e.downloadTotal??e.download_total??0,n=s.connectionStream.rows??new Map,l=e.connections??[];s.connections=l.map(d=>{let u=d.metadata??{},g=u.host||u.destinationIP||u.destination_ip||"unknown",f=d.rulePayload??d.rule_payload,m=[d.rule,f].filter(Boolean).join(","),C=n.get(d.id),$=d.upload??0,q=d.download??0,R=C&&a?Math.max(0,($-C.upload)/a):0,U=C&&a?Math.max(0,(q-C.download)/a):0;return{id:d.id,host:g,rule:m||"MATCH",chains:d.chains??[],upload:S($),download:S(q),uploadBytes:$,downloadBytes:q,uploadSpeedBytes:R,downloadSpeedBytes:U,speed:`${S(R)}/s up \xB7 ${S(U)}/s down`,age:d.start?d.start.slice(11,19):"live",start:d.start,metadata:u}}),a&&(s.traffic.upload=Math.max(0,(o-s.connectionStream.uploadTotal)/a/1024/1024),s.traffic.download=Math.max(0,(r-s.connectionStream.downloadTotal)/a/1024/1024)),s.connectionStream={at:t,uploadTotal:o,downloadTotal:r,rows:new Map(l.map(d=>[d.id,{upload:d.upload,download:d.download}]))},s.controllerStatus="controller live stream"}function ot(e){if(!e)return!1;let t=e.proxy_providers??[],a=e.rule_providers??[];return s.providers=t.map(o=>({name:o.name,type:o.kind,vehicle:o.vehicle_type,updated:o.updated_at??"unknown",health:o.extra?.healthCheck?.lastResult??o.extra?.healthcheck?.lastResult??"Unknown",proxies:o.proxies?.length??0})),s.ruleProviders=a.map(o=>({name:o.name,type:o.kind,behavior:o.behavior??o.vehicle_type,updated:o.updated_at??"unknown",rules:o.rules?.length??0})),!0}function ke(){let e=pe(s.logSearch);return s.logs.filter(t=>{let a=de(t.level),o=s.logFilter==="all"||a===s.logFilter,r=[t.time,a,t.source,t.message,...(t.fields??[]).map(l=>`${l.key}=${l.value}`)].join(" "),n=!s.logSearch||(e?e.test(r):r.toLowerCase().includes(s.logSearch.toLowerCase()));return o&&n}).slice(0,ie)}function Fe(){return ke().map(t=>`
          <article class="log-line ${c(t.level)}">
            <time>${c(t.time)}</time>
            <b>${c(t.level)}</b>
            <span>${c(t.source)}</span>
            <p>
              ${c(t.message)}
              ${(t.fields??[]).length?`<small>${t.fields.map(a=>`${c(a.key)}=${c(a.value)}`).join(" \xB7 ")}</small>`:""}
            </p>
          </article>
        `).join("")||`<p class="empty">No ${s.logFilter==="all"?"":`${s.logFilter.toUpperCase()} `}logs for this filter.</p>`}function Ce(){let e=document.querySelector(".log-stream");if(!e)return!1;let t=document.querySelector(".logs-layout .toolbar-panel h3");return t&&(t.textContent=`${ke().length} log entries${s.logsPaused?" paused":""}`),e.innerHTML=Fe(),!0}function Ie(){w.logStreamFrame===null&&(w.logStreamFrame=window.requestAnimationFrame(()=>{w.logStreamFrame=null,s.activePage==="logs"&&(Ce()||se())}))}function He(){let e=pe(s.connectionSearch),t=s.connections.filter(r=>{let n=r.metadata??{},l=[r.host,r.rule,...r.chains??[],n.processPath,n.process_path,n.sourceIP,n.source_ip,n.destinationIP,n.destination_ip,n.network,n.type].filter(Boolean).join(" ");return!s.connectionSearch||(e?e.test(l):l.toLowerCase().includes(s.connectionSearch.toLowerCase()))}),a={host:r=>r.host,speed:r=>r.uploadSpeedBytes+r.downloadSpeedBytes,upload:r=>r.uploadBytes,download:r=>r.downloadBytes,age:r=>Date.parse(r.start||"")||0},o=a[s.connectionSort]??a.age;return[...t].sort((r,n)=>{let l=o(r),d=o(n),u=typeof l=="string"?l.localeCompare(String(d)):l-d;return s.connectionSortDesc?-u:u}).slice(0,Me)}function rt(){let e=pe(s.ruleSearch);return s.rules.filter(t=>{let a=[t.index,t.type,t.payload,t.proxy,t.hits].filter(Boolean).join(" ");return!s.ruleSearch||(e?e.test(a):a.toLowerCase().includes(s.ruleSearch.toLowerCase()))}).slice(0,2e3)}function nt(){let e=document.getElementById("nav");e.innerHTML=s.payload.pages.filter(t=>Pe.has(t.id)).map((t,a)=>`
        <button class="nav-item${t.id===s.activePage?" active":""}" data-page="${c(t.id)}">
          <span>${a+1}</span>
          <b>${c(t.title)}</b>
        </button>
      `).join("")}function L(e,t,a,o={}){let r=s.toggles[e]?"checked":"",n=o.disabled?"disabled":"";return`
    <label class="toggle-row ${o.disabled?"disabled":""}">
      <span>
        <b>${c(t)}</b>
        <small>${c(a)}</small>
      </span>
      <input type="checkbox" data-toggle="${c(e)}" ${r} ${n} />
      <i></i>
    </label>
  `}function K(e,t,a={}){let o=s.toggles[e]?"checked":"",r=a.disabled?"disabled":"";return`
    <label class="inline-switch ${a.disabled?"disabled":""}">
      <span class="visually-hidden">${c(t)}</span>
      <input type="checkbox" data-toggle="${c(e)}" ${o} ${r} />
      <i></i>
    </label>
  `}function ze(){return`
    <svg class="cfw-cat-logo" viewBox="0 0 112 96" aria-hidden="true">
      <path d="M23 86c-12 0-19-8-19-17 0-9 7-15 16-15 4 0 7 1 10 3l4-43 17 16 12-1 18-17 6 72c-17 2-40 2-64 2Z" />
      <path class="cat-tail" d="M22 70c-14 4-24-4-20-15 2-6 8-9 13-7" />
      <circle cx="43" cy="45" r="4" />
      <circle cx="71" cy="45" r="4" />
      <path class="cat-mouth" d="M54 58c3 3 6 3 9 0" />
    </svg>
  `}function Oe(e){let t='width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"';switch(e){case"terminal":return`<svg ${t}><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm1 3v2l3 2-3 2v2l5-3.5L5 7zm7 8h6v2h-6v-2z"/></svg>`;case"sync":return`<svg ${t}><path d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46A7.93 7.93 0 0 0 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74A7.93 7.93 0 0 0 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z"/></svg>`;case"sync-off":return`<svg ${t}><path d="M20 12c0-4.42-3.58-8-8-8V1L8 5l1.7 1.7C12.9 6.8 15.2 8.9 16.1 11.5l1.7 1.7c.13-.4.2-.8.2-1.2zM4.27 3 3 4.27l2.05 2.05A7.95 7.95 0 0 0 4 12c0 4.42 3.58 8 8 8v3l4-4-1.3-1.3L19.73 21 21 19.73 4.27 3zM12 18c-3.31 0-6-2.69-6-6 0-1.3.41-2.5 1.11-3.48L14.48 16.9A5.9 5.9 0 0 1 12 18z"/></svg>`;case"info":return`<svg ${t}><path d="M12 2a10 10 0 1 0 .001 20.001A10 10 0 0 0 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>`;case"device-hub":return`<svg ${t}><path d="M17 16h-2v-2h2v2zm-4 0h-2v-2h2v2zm-4 0H7v-2h2v2zm10-6h-2V8h2v2zm-4 0h-2V8h2v2zm-4 0H7V8h2v2zm10-6H5c-1.1 0-2 .9-2 2v14h18V6c0-1.1-.9-2-2-2zm0 14H5V6h14v10z"/></svg>`;case"memory":return`<svg ${t}><path d="M15 9H9v6h6V9zm-2 4h-2v-2h2v2zm8-2V9h-2V7c0-1.1-.9-2-2-2h-2V3h-2v2h-2V3H9v2H7c-1.1 0-2 .9-2 2v2H3v2h2v2H3v2h2v2c0 1.1.9 2 2 2h2v2h2v-2h2v2h2v-2h2c1.1 0 2-.9 2-2v-2h2v-2h-2v-2h2zm-4 6H7V7h10v10z"/></svg>`;case"dns":return`<svg ${t}><path d="M20 13H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1v-6c0-.55-.45-1-1-1zM7 19c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM20 3H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1zM7 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>`;case"play":return`<svg ${t}><path d="M8 5v14l11-7L8 5z"/></svg>`;case"public":return`<svg ${t}><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>`;case"settings":return`<svg ${t}><path d="M19.14 12.94c.04-.31.06-.63.06-.94s-.02-.63-.06-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.49.49 0 0 0-.59-.22l-2.39.96a7.2 7.2 0 0 0-1.62-.94l-.36-2.54A.48.48 0 0 0 14 2h-4a.48.48 0 0 0-.48.42l-.36 2.54c-.59.24-1.13.56-1.62.94l-2.39-.96a.49.49 0 0 0-.59.22L2.65 8.87a.49.49 0 0 0 .12.61l2.03 1.58c-.04.31-.06.63-.06.94s.02.63.06.94L2.77 14.52a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.42.48.42h4c.24 0 .44-.18.48-.42l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32a.49.49 0 0 0-.12-.61l-2.01-1.58zM12 15.5A3.5 3.5 0 1 1 12 8.5a3.5 3.5 0 0 1 0 7z"/></svg>`;case"history":return`<svg ${t}><path d="M13 3a9 9 0 0 0-9 9H1l3.89 3.89.07.14L9 12H6a7 7 0 0 1 7-7 7 7 0 0 1 7 7 7 7 0 0 1-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42A8.95 8.95 0 0 0 13 21a9 9 0 0 0 0-18zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/></svg>`;default:return""}}function E(e,t,a,o={}){let r=o.tone?` ${o.tone}`:"",n=o.active?" active":"";return`<button type="button" class="general-icon${r}${n}" data-action="${c(e)}" title="${c(a)}">${Oe(t)}</button>`}function Ge(e){let t=e["bind-address"]??e.bindAddress??(s.toggles.allowLan?"*":"127.0.0.1");return String(t)}function it(e){return e==="Enabled"?"ok":Ee(e)?"warn":"muted"}function lt(){let e=s.kernelCompare;if(!e?.comparison)return`
      <div class="cfw-row">
        <div class="cfw-row-left">Core Bench</div>
        <div class="cfw-row-right">
          <button type="button" class="cfw-text-button" data-action="load-kernel-compare">Load measured clash-rs vs mihomo</button>
        </div>
      </div>
    `;let t=e.comparison.headline??{},a=e.comparison.narrative??{},o=t.cold_start_speedup_x!=null?`${t.cold_start_speedup_x}\xD7`:"n/a",r=t.controller_api_speedup_x!=null?`${t.controller_api_speedup_x}\xD7`:"n/a",n=t.weak_net_success_delta_pp!=null?`${t.weak_net_success_delta_pp>=0?"+":""}${t.weak_net_success_delta_pp}pp`:"n/a",l=e.measured_at?String(e.measured_at).slice(0,10):"local";return`
    <div class="cfw-row cfw-row-bench">
      <div class="cfw-row-left">
        <span>Core Bench</span>
        <span class="general-icons">
          ${E("show-kernel-compare","info","Show measured clash-rs vs mihomo details")}
        </span>
      </div>
      <div class="cfw-row-right">
        <button type="button" class="cfw-text-button" data-action="show-kernel-compare" title="${c(a.speed??"")} ${c(a.weak_net??"")}">
          clash-rs ${c(o)} cold \xB7 ${c(r)} API \xB7 weak-net ${c(n)} \xB7 ${c(l)}
        </button>
      </div>
    </div>
  `}function me(e){!e||typeof e!="object"||(s.updateInfo={available:!!e.available,current:e.current??s.payload?.product?.version,version:e.version??null,notes:e.notes??null,error:e.error??null})}async function je(e=!1){if(s.kernelCompare&&!e)return s.kernelCompare;try{return s.kernelCompare=await p("kernel_compare_report"),s.kernelCompare}catch(t){return i("warning","bench",`Kernel compare unavailable: ${t.message??String(t)}`),null}}async function Ve(e){me(e),D({autoCheck:!0,checking:!1,result:e})}function D(e={}){let t=s.payload?.product??T.product,a=e.result?{available:!!e.result.available,current:e.result.current??t.version,version:e.result.version??null,notes:e.result.notes??null,error:e.result.error??null,date:e.result.date??null}:s.updateInfo;s.glassDialog={kind:"product-about",payload:{checking:!!e.checking,autoCheck:!!e.autoCheck,update:a}},_()}function ct(e){if(e?.checking)return"Checking for updates\u2026";let t=e?.update;return t?.error?`Update check failed: ${t.error}`:t?.available&&t?.version?`Update available: v${t.version}`:t&&t.available===!1?`You\u2019re up to date (v${t.current??s.payload?.product?.version??"\u2014"})`:"Check GitHub releases for new builds."}function We(){let e=s.settingsSnapshot?.settings??y.settings,a=(s.payload.product??T.product).version??"0.3.4",o=s.updateInfo,r=o?.available&&o?.version?`<button type="button" class="cfw-update-badge" data-action="check-for-updates" title="Update available \u2014 click to download">\u2192 v${c(String(o.version))}</button>`:"",n=s.coreStatus??I,l=n.state==="Running",d=e.external_controller_host??"127.0.0.1",u=e.external_controller_port??9090,g=e.coreKind??e.core_kind??"clash_rs",f=s.controllerVersion?.version??(l?"Connected":n.state),m=l?"cfw-status-dot on":"cfw-status-dot",C=s.logLevel??e.logLevel??e["log-level"]??"info",$=ee(s.serviceModeStatus),q=s.serviceModeStatus==="Enabled",R=!!(e.randomMixedPort??e.random_mixed_port),U=Ge(e),J=it(s.serviceModeStatus);return`
    <div class="cfw-general-view">
      <section class="cfw-header">
        <div class="cfw-app-mark">${ze()}</div>
        <div class="cfw-title">
          <span>Clash for Mac</span>
          <small>v${c(a)}${r}</small>
        </div>
      </section>

      <section class="cfw-content">
        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Port</span>
            <span class="general-icons">
              ${E("copy-proxy-exports","terminal","Copy proxy export commands for Terminal")}
              ${E("toggle-random-mixed-port",R?"sync":"sync-off","random mixed port",{active:R})}
            </span>
          </div>
          <div class="cfw-row-right">
            <input class="cfw-number" data-mixed-port type="number" min="1" max="65535" value="${e.mixed_port}" aria-label="mixed-port" ${R?"disabled":""}>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Allow LAN</span>
            <span class="general-icons">
              ${E("allow-lan-info","info","Turn on to listen on all interfaces by default, or else only listen on 127.0.0.1. Change Bind Address to pick an interface.")}
              ${E("show-network-interfaces","device-hub","network interfaces")}
            </span>
          </div>
          <div class="cfw-row-right">
            <button type="button" class="cfw-text-button" data-action="edit-bind-address" title="Edit bind address">Bind: ${c(U)}</button>
            ${K("allowLan","Allow LAN")}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Log Level</div>
          <div class="cfw-row-right">
            <select class="cfw-select" data-log-level>
              ${["info","warning","error","debug","trace","silent"].map(j=>`
                <option value="${j}" ${C===j?"selected":""}>${j}</option>
              `).join("")}
            </select>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">IPv6</div>
          <div class="cfw-row-right">${K("enableIpv6","IPv6")}</div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Clash Core</span>
            <span class="general-icons">
              ${E("preview-runtime-config","memory","Preview the final configuration file that was submitted to Clash Core")}
              ${E("dns-query","dns","Resolve a host using Clash core")}
              ${E("script-test","play","Test script using by Script mode")}
            </span>
          </div>
          <div class="cfw-row-right">
            <button type="button" class="cfw-text-button core-version-link" data-action="open-controller-dashboard" title="Open controller dashboard">
              <i class="${m}"></i>
              <span>${c(String(g))} \xB7 ${c(f)}${l?` (${c(String(u))})`:""}</span>
            </button>
            <button type="button" class="general-icon" data-action="${n.state==="MissingBinary"?"install-pinned-core":l?"stop-core":"start-core"}" title="${l?"Stop core":n.state==="MissingBinary"?"Install pinned core":"Start core"}">${l?"\u25A0":"\u25B6"}</button>
          </div>
        </div>

        ${lt()}

        <div class="cfw-row">
          <div class="cfw-row-left">Home Directory</div>
          <div class="cfw-row-right">
            <button class="cfw-text-button" data-action="open-home-directory">Open Folder</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">GeoIP Database</div>
          <div class="cfw-row-right">
            <button class="cfw-text-button" data-action="update-geoip-database" title="${s.geoipStatus?.path?c(s.geoipStatus.path):"Download / refresh GeoIP database"}">${c(De(s.geoipStatus,s.geoipUpdating))}</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Service Mode</span>
            <span class="general-icons">
              <span class="general-icon ${J}" title="Service Mode status">${Oe("public")}</span>
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${$}</span>
            <button class="cfw-text-button" data-action="manage-service-mode">Manage</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>TUN Mode</span>
            <span class="general-icons">
              ${E("tun-info","info","To enable this mode, please install Service Mode first!")}
              ${E("tun-settings","settings","Settings")}
              ${E("tun-reset-dns","history","System DNS servers that will be set after TUN Mode is disabled")}
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${Te(s.tunRuntime?.tun_mode??s.toggles.tunMode,s.serviceModeStatus,s.tunRuntime)}</span>
            ${K("tunMode","TUN Mode",{disabled:!q})}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Mixin</span>
            <span class="general-icons">
              ${E("mixin-info","info","Mixin merges YAML into the generated config before reload. Docs: profile mixin in Settings.")}
              ${E("edit-mixin","settings","Edit Mixin content")}
            </span>
          </div>
          <div class="cfw-row-right">${K("mixin","Mixin")}</div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">System Proxy</div>
          <div class="cfw-row-right">${K("systemProxy","System Proxy")}</div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Start with macOS</div>
          <div class="cfw-row-right">${K("startAtLogin","Start with macOS")}</div>
        </div>
      </section>
    </div>
  `}function Ke(e){return e==null?"pending":e<=0?"dead":e<80?"fast":e<180?"mid":"slow"}function Ye(e){return e==null?"Pending":e<=0?"Timeout":`${e} ms`}function Be(){if(typeof document<"u"&&document.hidden)return 2;let e=Number(navigator.hardwareConcurrency)||8;return Math.max(4,Math.min(16,e))}function ve(){w.delayTestGeneration=(w.delayTestGeneration??0)+1,s.toggles.testingDelays=!1}function dt(){let e=document.querySelector("[data-proxy-node-grid]");if(!e)return[];let t=e.getBoundingClientRect(),a=[];return e.querySelectorAll("[data-proxy-node]").forEach(o=>{let r=o.getBoundingClientRect();if(r.bottom>=t.top&&r.top<=t.bottom){let n=o.getAttribute("data-proxy-node");n&&a.push(n)}}),a}function pt(e){let t=new Set(dt()),a=[],o=[];for(let r of e)t.has(r)?a.push(r):o.push(r);return a.length?[...a,...o]:e}function fe(e,t){let a=typeof t=="number"&&Number.isFinite(t)?t:0;s.proxyGroups.forEach(o=>{o.options.forEach(r=>{r.name===e&&(r.delay=a,r.dead=a<=0)})})}function Y(e){let t=e?new Set(e):null;document.querySelectorAll("[data-proxy-delay]").forEach(o=>{let r=o.getAttribute("data-proxy-delay");if(!r||t&&!t.has(r))return;let n=null;for(let l of s.proxyGroups){let d=l.options.find(u=>u.name===r);if(d){n=d.delay;break}}o.className=Ke(n),o.textContent=Ye(n)});let a=document.querySelector('[data-action="delay-test"]');a&&(a.classList.toggle("active",!!s.toggles.testingDelays),a.disabled=!!s.toggles.testingDelays)}function qe(e){e.forEach(t=>{let a=null;for(let o of s.proxyGroups){let r=o.options.find(n=>n.name===t);if(r){a=r;break}}a&&(a.delay===null||a.delay===void 0)&&fe(t,0)}),Y(e)}function ut(e){return String(e).replace(/[^a-z0-9_-]/gi,"-")}function te(e){return["selector","relay"].includes(String(e??"").toLowerCase())}function ue(e){let t='width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"';switch(e){case"scroll":return`<svg ${t} fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/><circle cx="18.5" cy="18.5" r="3.2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M20.8 20.8L23 23" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`;case"report":return`<svg ${t} fill="currentColor"><path d="M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3c-.72 0-1.3-.58-1.3-1.3s.58-1.3 1.3-1.3 1.3.58 1.3 1.3-.58 1.3-1.3 1.3zm1-4.3h-2V7h2v6z"/></svg>`;case"report-off":return`<svg ${t} fill="currentColor"><path d="M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3c-.72 0-1.3-.58-1.3-1.3s.58-1.3 1.3-1.3 1.3.58 1.3 1.3-.58 1.3-1.3 1.3zm1-4.3h-2V7h2v6z" opacity=".38"/></svg>`;case"delay":return`<svg ${t} fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12a10 10 0 0 1 20 0"/><path d="M5 12a7 7 0 0 1 14 0"/><path d="M8.5 12a3.5 3.5 0 0 1 7 0"/><path d="M12 12V7.5" stroke-width="2"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/></svg>`;case"eye":return`<svg ${t} fill="currentColor"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>`;case"eye-off":return`<svg ${t} fill="currentColor"><path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/></svg>`;default:return""}}function gt(e){return e?e.dead?!0:typeof e.delay=="number"&&e.delay<=0:!1}function ft(){let e=s.proxyFilter.trim().toLowerCase(),t=s.proxyGroups.map(f=>({...f,options:f.options.filter(m=>{let C=!e||f.name.toLowerCase().includes(e)||m.name.toLowerCase().includes(e),$=s.toggles.hideUnavailable&&gt(m)&&f.now!==m.name;return C&&!$})})).filter(f=>f.options.length||f.name.toLowerCase().includes(e)),a=t.find(f=>f.name===s.activeProxyGroup)??t.find(f=>te(f.type)&&/选择|select|proxy|节点/i.test(f.name))??t.find(f=>te(f.type)&&f.name.toUpperCase()!=="GLOBAL")??t.find(f=>te(f.type))??t[0]??null,o=a?te(a.type):!1,r=!!s.toggles.hideUnavailable,n=s.toggles.showProxiesList!==!1,l=s.proxyBlinkNode,d=s.controllerStatus==="controller live"&&s.proxyGroups.length>0,u=s.controllerStatus==="controller live"&&s.proxyGroups.length===0?"Active profile has no proxy groups. Switch to a subscription with nodes.":"Controller unavailable. No live proxy groups are being displayed.";return`
    <div class="proxy-layout">
      ${d?`
      <div class="mode-switch proxy-mode-header" role="group" aria-label="Proxy mode">
        ${["Global","Rule","Direct","Script"].map(f=>`
          <button class="${s.mode===f?"selected":""}" data-mode="${f}">${f} <span>${ht(f)}</span></button>
        `).join("")}
      </div>`:""}

      <div class="cfw-proxy-page">
        ${a?`
          <div class="cfw-proxy-head">
            <div class="cfw-proxy-title">
              <span class="proxy-shield">\u25C7</span>
              <h2>${c(a.name)}</h2>
              <span class="proxy-type-badge">${c(a.type?.slice(0,1)??"S")}</span>
              <b>${c(a.now??"")}</b>
            </div>
            <div class="cfw-proxy-tools">
              <input class="proxy-filter" data-proxy-filter placeholder="Filter" value="${c(s.proxyFilter)}" aria-label="Filter proxies" />
              <button class="proxy-tool" data-action="scroll-to-selected-proxy" title="Scroll to selected proxy">${ue("scroll")}</button>
              <button class="proxy-tool ${r?"active":""}" data-action="toggle-hide-timed-out" title="Show/Hide timed-out proxies">${ue(r?"report-off":"report")}</button>
              <button class="proxy-tool ${s.toggles.testingDelays?"active":""}" data-action="delay-test" title="Test latency" ${s.toggles.testingDelays?"disabled":""}>${ue("delay")}</button>
              <button class="proxy-tool ${n?"active":""}" data-action="toggle-show-proxies" title="Show/hide proxies">${ue(n?"eye":"eye-off")}</button>
            </div>
          </div>
          <div class="cfw-proxy-content">
            ${n?`
            <div class="cfw-node-grid" data-proxy-node-grid>
              ${a.options.map(f=>`
                <button class="cfw-node-card ${a.now===f.name?"selected":""} ${l===f.name?"blink":""} ${o?"":"readonly"}" data-proxy-node="${c(f.name)}" ${o?`data-group="${c(a.name)}" data-node="${c(f.name)}"`:"disabled"} title="${o?"Select proxy":"This Clash group type is controlled by the core"}">
                  <i></i>
                  <span>
                    <strong>${mt(f.name)}${c(f.name)}</strong>
                    <small>${c(f.kind??"Proxy")} ${f.udp===!1?"":"<em>UDP</em>"}</small>
                  </span>
                  <b class="${Ke(f.delay)}" data-proxy-delay="${c(f.name)}">${Ye(f.delay)}</b>
                </button>
              `).join("")}
            </div>
            `:'<p class="empty proxy-list-hidden">Proxies hidden \u2014 click the eye to show this group\u2019s nodes.</p>'}
            <aside class="cfw-group-rail">
              ${t.map(f=>`
                <button class="${f.name===a.name?"active":""}" data-proxy-group-tab="${c(f.name)}" title="${c(f.name)}">${c(vt(f.name))}</button>
              `).join("")}
            </aside>
          </div>
        `:`<p class="empty">${c(u)}</p>`}
      </div>
    </div>
  `}function ht(e){return{Global:"\u2197",Rule:"\u219D",Direct:"\u2192",Script:"\u21AD"}[e]??""}function mt(e){let t=String(e??"");return/[\u{1F1E6}-\u{1F1FF}]/u.test(t)?"":/^(DIRECT|REJECT)$/i.test(t)?"\u2022 ":""}function vt(e){let t=String(e??"").trim();if(!t)return"?";if(/^GLOBAL$/i.test(t))return"GLOBAL";let a=t.replace(/[\u{1F1E6}-\u{1F1FF}]/gu,"").replace(/[|｜丨&＆/\\()[\]{}【】「」『』·•._\-:：;；,，。!！?？"'“”‘’]+/g,"").replace(/\s+/g,"");return([...a].filter(r=>/[\u4e00-\u9fffA-Za-z0-9]/.test(r)).join("")||a||t).slice(0,6)}function yt(e){try{return new URL(e).host}catch{return e||"local file"}}function bt(e){return e.updateInterval?`interval ${e.updateInterval}`:e.sourceUrl?"remote":"local"}function Xe(e){if(!e||typeof e!="string")return null;let t=Object.create(null);for(let g of e.split(/[;\s]+/)){let f=g.indexOf("=");f<=0||(t[g.slice(0,f).trim().toLowerCase()]=g.slice(f+1).trim())}let a=Number(t.upload),o=Number(t.download),r=Number(t.total),n=Number(t.expire),l=(Number.isFinite(a)?a:0)+(Number.isFinite(o)?o:0),d=null;Number.isFinite(r)&&r>0&&(d=Math.max(0,Math.min(100,l/r*100)));let u=null;if(Number.isFinite(n)&&n>0){let g=new Date(n*1e3);if(!Number.isNaN(g.getTime())){let f=m=>String(m).padStart(2,"0");u=`${g.getFullYear()}-${f(g.getMonth()+1)}-${f(g.getDate())}`}}return{used:l,total:Number.isFinite(r)&&r>0?r:null,percent:d,expireDate:u}}function xe(e){if(!Number.isFinite(e)||e<0)return"0B";let t=["B","KB","MB","GB","TB"],a=e,o=0;for(;a>=1024&&o<t.length-1;)a/=1024,o+=1;return o===0?`${Math.round(a)}B`:`${a.toFixed(1)}${t[o]}`}function wt(e){if(!Number.isFinite(e)||e<=0)return"unknown";let t=Date.now()-e*1e3;if(t<0)return new Date(e*1e3).toLocaleString();let a=Math.floor(t/1e3);return a<45?"a few seconds":a<90?"1 minute":a<3600?`${Math.floor(a/60)} minutes`:a<5400?"1 hour":a<86400?`${Math.floor(a/3600)} hours`:new Date(e*1e3).toLocaleString()}function _t(e){let t=Xe(e.subscriptionUserinfo);if(t&&(t.total!=null||t.expireDate)){let a=[];return t.total!=null?(a.push(`<span>${c(xe(t.used))}</span>`),a.push(`<span>${c(xe(t.total))}</span>`)):a.push(`<span>${c(xe(t.used))}</span>`),t.expireDate&&a.push(`<span>${c(t.expireDate)}</span>`),a.join("")}return`
    <span>${c(e.traffic)}</span>
    <span>${e.rules.toLocaleString()} rules</span>
    <span>${c(bt(e))}</span>
  `}function St(e){let t=Xe(e.subscriptionUserinfo);return t?.percent!=null?t.percent:0}var xt=[{id:"select",label:"Select",icon:"check",needsInactive:!0},{id:"open-web",label:"Open web page",icon:"home",remoteOnly:!1,needsHomeWeb:!0},{id:"edit",label:"Edit",icon:"edit"},{id:"edit-external",label:"Edit externally",icon:"edit"},{id:"update",label:"Update",icon:"refresh",remoteOnly:!0},{id:"reveal",label:"Show in folder",icon:"folder"},{id:"diff",label:"Diff",icon:"diff",remoteOnly:!0},{id:"proxies",label:"Edit proxies section",icon:"send"},{id:"rules",label:"Edit rules section",icon:"rules"},{id:"copy",label:"Copy",icon:"copy"},{id:"qrcode",label:"QRCode",icon:"qr",remoteOnly:!0},{id:"parsers",label:"Parsers",icon:"tree",remoteOnly:!0},{id:"run-script",label:"Run script",icon:"code"},{id:"settings",label:"Settings",icon:"gear"},{id:"delete",label:"Delete",icon:"trash",danger:!0}];function $t(e){let t={check:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9.2 16.6 4.8 12.2l1.4-1.4 3 3 8.6-8.6 1.4 1.4-10 10z"/></svg>',home:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 3.2 3.8 10.2v9.6h5.4v-5.4h5.6v5.4h5.4v-9.6L12 3.2z"/></svg>',edit:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M4.5 16.9 15.8 5.6l2.6 2.6L7.1 19.5H4.5v-2.6zm14.3-11.7 1.5 1.5c.4.4.4 1 0 1.4l-1.2 1.2-2.6-2.6 1.2-1.2c.4-.4 1-.4 1.4 0z"/></svg>',refresh:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 5a7 7 0 0 1 6.3 4H16v2h5.5V5.5H19v1.7A9 9 0 1 0 21 12h-2a7 7 0 1 1-7-7z"/></svg>',folder:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3.5 6.5A2 2 0 0 1 5.5 4.5h4l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2v-11z"/></svg>',diff:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M7 4h2v5H7V4zm0 11h2v5H7v-5zm8-7.5 3.5 3.5L15 14.5V12h-4v-2h4V7.5zM5 10h6v2H5v-2z"/></svg>',send:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3.2 11.2 20 3.5 12.3 20.8l-1.7-6.4-7.4-3.2zm4.4 2.3 4.2 1.8 3.3-7.4-7.5 5.6z"/></svg>',rules:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M5 5h14v2H5V5zm0 6h14v2H5v-2zm0 6h10v2H5v-2z"/></svg>',copy:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M8 7h10v12H8V7zm-3 3H4V4h11v2H5v4zm3-1h2v10h8v2H8V9z"/></svg>',qr:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M4 4h7v7H4V4zm2 2v3h3V6H6zm7-2h7v7h-7V4zm2 2v3h3V6h-3zM4 13h7v7H4v-7zm2 2v3h3v-3H6zm9 0h2v2h-2v-2zm4 0h2v2h-2v-2zm-4 4h2v2h-2v-2zm2 2h4v2h-4v-2zm2-4h2v4h-2v-4z"/></svg>',tree:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M10 3h4v4h-4V3zm-5 7h4v4H5v-4zm10 0h4v4h-4v-4zM7 13h2v3h6v-3h2v5H7v-5z"/></svg>',code:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="m8.2 7.2 1.4 1.4L6.8 12l2.8 3.4-1.4 1.4L4 12l4.2-4.8zm7.6 0L20 12l-4.2 4.8-1.4-1.4 2.8-3.4-2.8-3.4 1.4-1.4z"/></svg>',gear:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M11 3h2l.4 2.2a6.8 6.8 0 0 1 1.8.8l2-1.1 1.4 1.4-1.1 2a6.8 6.8 0 0 1 .8 1.8L20.5 11v2l-2.2.4a6.8 6.8 0 0 1-.8 1.8l1.1 2-1.4 1.4-2-1.1a6.8 6.8 0 0 1-1.8.8L13 20.5h-2l-.4-2.2a6.8 6.8 0 0 1-1.8-.8l-2 1.1-1.4-1.4 1.1-2a6.8 6.8 0 0 1-.8-1.8L3.5 13v-2l2.2-.4a6.8 6.8 0 0 1 .8-1.8l-1.1-2 1.4-1.4 2 1.1a6.8 6.8 0 0 1 1.8-.8L11 3zm1 6.5A2.5 2.5 0 1 0 12 14a2.5 2.5 0 0 0 0-5z"/></svg>',trash:'<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9 4h6l1 2h4v2H4V6h4l1-2zm1 5h2v9h-2V9zm4 0h2v9h-2V9zM7 9h2v9H7V9z"/></svg>'};return t[e]??t.gear}function A(){s.profileContextMenu=null,s.glassDialog=null,_()}function kt(e,t,a){s.glassDialog=null,s.profileContextMenu={id:e,x:t,y:a},_()}function _(){let e=document.getElementById("glass-menu-root");if(!e)return;let t=[];if(s.profileContextMenu){let a=s.profiles.find(o=>o.id===s.profileContextMenu.id);if(a){let o=!!a.sourceUrl,n=xt.filter(l=>!(l.needsHomeWeb&&!a.homeWeb||l.remoteOnly&&!o||l.needsInactive&&a.active)).map(l=>`
        <button type="button" class="glass-menu-item ${l.danger?"danger":""}" data-profile-menu="${l.id}" data-profile-id="${c(a.id)}">
          <span class="glass-menu-icon">${$t(l.icon)}</span>
          <span>${c(l.label)}</span>
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
          <label>Name<input data-glass-copy-name value="${c(`${o.name} copy`)}" /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-copy-confirm="${c(o.id)}">Copy</button>
          </div>
        </div>
      `);else if(o&&a.kind==="settings")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Edit profile information">
          <h3>Edit profile information</h3>
          <label>Name<input data-glass-settings-name value="${c(o.name)}" /></label>
          <label>URL<input data-glass-settings-url value="${c(o.sourceUrl??"")}" placeholder="https://..." /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-settings-confirm="${c(o.id)}">Save</button>
          </div>
        </div>
      `);else if(o&&a.kind==="delete")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Delete profile">
          <h3>Delete profile</h3>
          <p class="glass-dialog-copy">Are you sure to delete \u201C${c(o.name)}\u201D? This removes the managed YAML file.</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>No</button>
            <button type="button" class="glass-btn danger" data-glass-delete-confirm="${c(o.id)}">Yes</button>
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
          <pre class="glass-code">${c(a.payload??"")}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
            <button type="button" class="glass-btn" data-glass-copy-text>Copy</button>
          </div>
        </div>
      `);else if(a.kind==="network-interfaces"){let r=(a.payload??[]).map(n=>`
        <tr>
          <td>${c(n.service)}</td>
          <td>${c(n.bsd_device??n.bsdDevice??"\u2014")}</td>
          <td>${c(n.service_type??n.serviceType??"\u2014")}</td>
          <td>${n.is_default_route||n.isDefaultRoute?"default":""}</td>
        </tr>`).join("");t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="Network interfaces">
          <h3>Network interfaces</h3>
          <p class="glass-dialog-copy">Default route: ${c(a.defaultRoute??"unknown")}</p>
          <div class="glass-table-wrap"><table class="glass-table"><thead><tr><th>Service</th><th>Device</th><th>Type</th><th></th></tr></thead><tbody>${r||'<tr><td colspan="4">No services</td></tr>'}</tbody></table></div>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button></div>
        </div>
      `)}else if(a.kind==="bind-address")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Bind address">
          <h3>Bind address</h3>
          <p class="glass-dialog-copy">Use 127.0.0.1 for localhost only, * for all interfaces, or a specific IP.</p>
          <label>Address<input data-glass-bind-address value="${c(a.payload??"*")}" /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-bind-confirm>Save</button>
          </div>
        </div>
      `);else if(a.kind==="dns-query")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="DNS query">
          <h3>Resolve via Clash core</h3>
          <label>Name<input data-glass-dns-name value="${c(a.payload?.name??"www.gstatic.com")}" /></label>
          <label>Type<input data-glass-dns-type value="${c(a.payload?.type??"A")}" /></label>
          <pre class="glass-code">${c(a.payload?.result??"Enter a name and Query.")}</pre>
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
          <textarea class="glass-textarea" data-glass-mixin-yaml rows="16" spellcheck="false">${c(a.payload??"")}</textarea>
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
          <label>DNS hijack (one per line)<textarea data-glass-tun-dns-hijack rows="4" spellcheck="false">${c(r.dnsHijack??`any:53
[::]:53`)}</textarea></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-tun-settings-confirm>Save</button>
          </div>
        </div>
      `)}else if(a.kind==="tun-reset-dns")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Restore DNS">
          <h3>Restore DNS after TUN off</h3>
          <p class="glass-dialog-copy">These servers are applied with networksetup when you click Apply (CFW manage_history). Use Empty to clear overrides.</p>
          <label>DNS servers<textarea data-glass-restore-dns rows="5" spellcheck="false">${c(a.payload??"Empty")}</textarea></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn ghost" data-glass-restore-dns-save>Save</button>
            <button type="button" class="glass-btn" data-glass-restore-dns-apply>Apply now</button>
          </div>
        </div>
      `);else if(a.kind==="service-mode-manage")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Service Mode">
          <h3>Service Mode</h3>
          <p class="glass-dialog-copy">Status: ${c(ee(s.serviceModeStatus))}</p>
          <div class="glass-dialog-actions column">
            <button type="button" class="glass-btn" data-glass-service-install>Install / Enable</button>
            <button type="button" class="glass-btn ghost" data-glass-service-uninstall>Uninstall / Disable</button>
            <button type="button" class="glass-btn ghost" data-glass-service-login-items>Open Login Items</button>
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
          </div>
        </div>
      `);else if(a.kind==="info")t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Info">
          <h3>${c(a.payload?.title??"Info")}</h3>
          <p class="glass-dialog-copy">${c(a.payload?.body??"")}</p>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button></div>
        </div>
      `);else if(a.kind==="product-about"){let n=(s.payload?.product??T.product).version??"0.3.4",l=ct(a.payload),d=a.payload?.update,u=!!(d?.available&&d?.version&&!a.payload?.checking),g=d?.notes?`<p class="product-about-notes">${c(String(d.notes).slice(0,280))}</p>`:"";t.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog product-about" role="dialog" aria-label="About Clash for Mac">
          <div class="product-about-icon">${ze()}</div>
          <div class="product-about-name">Clash for Mac</div>
          <div class="product-about-sub">Powered by clash-rs &amp; mihomo</div>
          <div class="product-about-meta">
            <div>\u7248\u672C ${c(String(n))}</div>
            <div>\u53D1\u5E03\u4E8E Jul 21, 2026</div>
          </div>
          <div class="product-about-status">${c(l)}</div>
          ${g}
          <div class="glass-dialog-actions column">
            ${u?`<button type="button" class="glass-btn" data-glass-install-update>Download &amp; Install v${c(String(d.version))}</button>`:""}
            <button type="button" class="glass-btn ghost" data-glass-check-update ${a.payload?.checking?"disabled":""}>${a.payload?.checking?"Checking\u2026":"Check for Update"}</button>
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
          </div>
          <div class="product-about-copy">\xA9 Clash for Mac \xB7 MIT</div>
        </div>
      `)}}e.innerHTML=t.join(""),Ct(),Pt()}function Ct(){let e=document.querySelector(".glass-menu");if(!e||!s.profileContextMenu)return;let t=10,a=e.getBoundingClientRect(),o=s.profileContextMenu.x,r=s.profileContextMenu.y;o+a.width>window.innerWidth-t&&(o=Math.max(t,window.innerWidth-a.width-t)),r+a.height>window.innerHeight-t&&(r=Math.max(t,window.innerHeight-a.height-t)),e.style.left=`${Math.round(o)}px`,e.style.top=`${Math.round(r)}px`;let n=e.querySelector("[data-glass-menu-scroll]"),l=e.querySelector("[data-glass-menu-more]");if(n&&l){let d=()=>{let u=n.scrollHeight>n.clientHeight+2,g=n.scrollTop+n.clientHeight>=n.scrollHeight-2;l.hidden=!u||g};n.addEventListener("scroll",d,{passive:!0}),d()}}function Pt(){document.querySelectorAll("[data-glass-dismiss]").forEach(t=>{t.addEventListener("click",()=>A())}),document.querySelectorAll("[data-profile-menu]").forEach(t=>{t.addEventListener("click",async a=>{let o=a.currentTarget.dataset.profileMenu,r=a.currentTarget.dataset.profileId;s.profileContextMenu=null,_();try{await Qe(o,r)}catch(n){i("error","profile",`${o} failed: ${n.message??String(n)}`)}h()})}),document.querySelectorAll("[data-glass-copy-confirm]").forEach(t=>{t.addEventListener("click",async a=>{let o=a.currentTarget.dataset.glassCopyConfirm,r=document.querySelector("[data-glass-copy-name]")?.value?.trim();if(r){try{let n=await p("read_profile_text",{id:o}),l=await p("import_profile_text",{name:r,body:n.body,activate:!1});await k(),A(),i("info","profile",`Copied profile to ${l.name}`)}catch(n){i("error","profile",`Copy failed: ${n.message??String(n)}`)}h()}})}),document.querySelectorAll("[data-glass-settings-confirm]").forEach(t=>{t.addEventListener("click",async a=>{let o=a.currentTarget.dataset.glassSettingsConfirm,r=document.querySelector("[data-glass-settings-name]")?.value?.trim()??"",n=document.querySelector("[data-glass-settings-url]")?.value?.trim()??"";try{await p("update_profile_info",{id:o,name:r,url:n}),await k(),A(),i("info","profile",`Profile settings saved: ${r}`)}catch(l){i("error","profile",`Settings failed: ${l.message??String(l)}`)}h()})}),document.querySelectorAll("[data-glass-delete-confirm]").forEach(t=>{t.addEventListener("click",async a=>{a.preventDefault(),a.stopPropagation();let o=a.currentTarget.dataset.glassDeleteConfirm,r=s.profiles.find(n=>n.id===o);try{let n=await p("delete_profile",{id:o});await k(),A(),i(n?"warning":"info","profile",n?`Profile deleted: ${r?.name??o}`:`Profile already missing: ${o}`)}catch(n){i("error","profile",`Delete failed: ${n.message??String(n)}`)}h()})}),document.querySelectorAll("[data-glass-reset-confirm]").forEach(t=>{t.addEventListener("click",async a=>{a.preventDefault(),a.stopPropagation();try{let o=await p("reset_settings_snapshot");v(o),await k(),A(),i("warning","settings","cfw-settings.yaml reset to defaults")}catch(o){i("error","settings",`Reset failed: ${o.message??String(o)}`)}h()})}),document.querySelectorAll("[data-glass-geoip-confirm]").forEach(t=>{t.addEventListener("click",async a=>{if(a.preventDefault(),a.stopPropagation(),s.geoipUpdating)return;let o=document.querySelector("[data-glass-geoip-url]")?.value?.trim()??"";A(),s.geoipUpdating=!0,h();try{let r=await p("update_geoip_database",{url:o||null});s.geoipStatus=r.status,i("info","geoip",`Updated ${r.status.file_name} (${S(r.bytes)}) from ${r.source_url}`)}catch(r){i("warning","geoip",`GeoIP update failed: ${r.message??String(r)}`)}finally{s.geoipUpdating=!1,h()}})}),document.querySelectorAll("[data-glass-copy-text]").forEach(t=>{t.addEventListener("click",async()=>{let a=s.glassDialog?.payload??document.querySelector(".glass-code")?.textContent??"";try{await navigator.clipboard.writeText(String(a)),i("info","clipboard","Copied dialog text")}catch(o){i("warning","clipboard",o.message??String(o))}})}),document.querySelectorAll("[data-glass-bind-confirm]").forEach(t=>{t.addEventListener("click",async()=>{let a=document.querySelector("[data-glass-bind-address]")?.value?.trim()??"";try{let o=await p("set_bind_address",{address:a});v(o),A(),i("info","settings",`Bind address set to ${a}`),P().active&&await p("apply_active_profile")}catch(o){i("warning","settings",`Bind address failed: ${o.message??String(o)}`)}h()})}),document.querySelectorAll("[data-glass-dns-confirm]").forEach(t=>{t.addEventListener("click",async()=>{let a=document.querySelector("[data-glass-dns-name]")?.value?.trim()??"",o=document.querySelector("[data-glass-dns-type]")?.value?.trim()||"A";try{let r=await p("dns_query",{name:a,record_type:o,recordType:o});s.glassDialog={kind:"dns-query",payload:{name:a,type:o,result:JSON.stringify(r,null,2)}},_()}catch(r){s.glassDialog={kind:"dns-query",payload:{name:a,type:o,result:String(r.message??r)}},_()}})}),document.querySelectorAll("[data-glass-open-rules]").forEach(t=>{t.addEventListener("click",async()=>{A(),s.activePage="rules",await we(),h()})}),document.querySelectorAll("[data-glass-mixin-confirm]").forEach(t=>{t.addEventListener("click",async()=>{let a=document.querySelector("[data-glass-mixin-yaml]")?.value??"";try{let o=await p("write_settings_snapshot",{settings:{...x(),mixin_yaml:a,mixinYaml:a}});if(v(o),s.mixinYaml=a,A(),i("info","settings","Mixin YAML saved"),s.toggles.mixin&&P().active){let r=await p("apply_active_profile");i("info","settings",`Mixin reapplied (${S(r.bytes??0)})`)}}catch(o){i("warning","settings",`Mixin save failed: ${o.message??String(o)}`)}h()})}),document.querySelectorAll("[data-glass-tun-settings-confirm]").forEach(t=>{t.addEventListener("click",async()=>{let a=document.querySelector("[data-glass-tun-stack]")?.value??"mixed",o=!!document.querySelector("[data-glass-tun-auto-route]")?.checked,r=!!document.querySelector("[data-glass-tun-strict-route]")?.checked,n=document.querySelector("[data-glass-tun-dns-hijack]")?.value??`any:53
[::]:53`;try{let l=x(),d=await p("write_settings_snapshot",{settings:{...l,"tun-stack":a,tunStack:a,"tun-auto-route":o,tunAutoRoute:o,"tun-strict-route":r,tunStrictRoute:r,"tun-dns-hijack":n,tunDnsHijack:n}});if(v(d),A(),i("info","tun",`TUN settings saved (stack=${a})`),s.toggles.tunMode)try{await p("reapply_runtime_config"),i("info","tun","Runtime config reapplied (root core respawn when TUN owns core)")}catch(u){i("warning","tun",`Reapply after TUN settings failed: ${u.message??String(u)}`)}}catch(l){i("warning","tun",`TUN settings failed: ${l.message??String(l)}`)}h()})});let e=async t=>{let a=document.querySelector("[data-glass-restore-dns]")?.value??"Empty";try{let o=x(),r=await p("write_settings_snapshot",{settings:{...o,"restore-dns-servers":a,restoreDnsServers:a}});if(v(r),t){let n=await p("apply_restore_dns_servers",{servers:a});i("info","dns",n)}else i("info","dns","Restore DNS list saved");A()}catch(o){i("warning","dns",o.message??String(o))}h()};document.querySelectorAll("[data-glass-restore-dns-save]").forEach(t=>{t.addEventListener("click",()=>e(!1))}),document.querySelectorAll("[data-glass-restore-dns-apply]").forEach(t=>{t.addEventListener("click",()=>e(!0))}),document.querySelectorAll("[data-glass-service-install]").forEach(t=>{t.addEventListener("click",async()=>{try{let a=await p("enable_service_mode");s.serviceModeStatus=a,i("info","service",`Service Mode: ${ee(a)}`)}catch(a){i("warning","service",a.message??String(a))}A(),h()})}),document.querySelectorAll("[data-glass-service-uninstall]").forEach(t=>{t.addEventListener("click",async()=>{try{await p("disable_service_mode"),s.serviceModeStatus=await p("service_mode_status"),i("info","service","Service Mode disabled")}catch(a){i("warning","service",a.message??String(a))}A(),h()})}),document.querySelectorAll("[data-glass-service-login-items]").forEach(t=>{t.addEventListener("click",async()=>{try{await p("open_login_items_settings"),i("info","service","Opened Login Items settings")}catch(a){i("warning","service",a.message??String(a))}})}),document.querySelectorAll("[data-glass-check-update]").forEach(t=>{t.addEventListener("click",async()=>{D({autoCheck:!0,checking:!0,result:s.updateInfo});try{let a=await p("check_for_updates");me(a),i((a?.available,"info"),"updater",a?.available?`Update ${a.version} available`:`Already up to date (${a?.current??"current"})`),D({autoCheck:!0,checking:!1,result:a})}catch(a){i("warning","updater",`Update check failed: ${a.message??String(a)}`),D({autoCheck:!0,checking:!1,result:{available:!1,error:a.message??String(a),current:s.payload?.product?.version}})}})}),document.querySelectorAll("[data-glass-install-update]").forEach(t=>{t.addEventListener("click",async()=>{try{i("info","updater","Downloading and installing update\u2026"),D({autoCheck:!0,checking:!0,result:{...s.updateInfo,available:!0}}),await p("install_available_update")}catch(a){i("warning","updater",`Install failed: ${a.message??String(a)}`),D({autoCheck:!0,checking:!1,result:{...s.updateInfo,error:a.message??String(a)}})}})})}async function Qe(e,t){let a=s.profiles.find(o=>o.id===t);if(!a)throw new Error(`profile not found: ${t}`);switch(e){case"select":await $e(t);return;case"open-web":{if(!a.homeWeb)throw new Error("no profile-web-page-url for this subscription");await p("open_external_url",{url:a.homeWeb}),i("info","profile",`Opened web page for ${a.name}`);return}case"edit":await B(t,"edit"),i("info","profile",`edit editor opened for ${a.name}`);return;case"proxies":await B(t,"edit","proxies"),i("info","profile",`proxies section editor opened for ${a.name}`);return;case"rules":await B(t,"edit","rules"),i("info","profile",`rules section editor opened for ${a.name}`);return;case"edit-external":await p("open_profile_externally",{id:t}),i("info","profile",`Opened ${a.name} externally`);return;case"update":{if(!a.sourceUrl)throw new Error("local profile has no subscription URL");let o=a.active,r=await p("update_profile",{id:t});await k(),o&&await p("apply_active_profile"),i("info","profile",`${r.name} subscription updated${o?" and config.yaml reapplied":""}`);return}case"reveal":await p("reveal_profile",{id:t}),i("info","profile",`Show in folder: ${a.name}`);return;case"diff":await B(t,"diff"),i("info","profile",`Diff opened for ${a.name}`);return;case"copy":s.glassDialog={kind:"copy",id:t},_();return;case"qrcode":await B(t,"qrcode"),i("info","profile",`QRCode opened for ${a.name}`);return;case"parsers":await B(t,"parsers"),i("info","profile",`Parsers opened for ${a.name}`);return;case"run-script":await B(t,"parsers"),a.active?(await p("apply_active_profile"),i("info","profile",`Run script: reapplied parsers/mixin for active profile ${a.name}`)):i("info","profile",`Run script: parser pipeline runs on apply; select ${a.name} to execute against config.yaml`);return;case"settings":s.glassDialog={kind:"settings",id:t},_();return;case"delete":s.glassDialog={kind:"delete",id:t},_();return;default:throw new Error(`unknown profile menu action: ${e}`)}}function Mt(){return`
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
          <article class="cfw-profile-card ${e.active?"active":""}" data-profile-card="${c(e.id)}">
            <i></i>
            <div class="profile-card-main">
              <h3>${c(e.name)}</h3>
              <p>${c(e.sourceUrl?yt(e.sourceUrl):"local file")} (${c(e.updated)})</p>
              <div class="profile-usage">
                ${_t(e)}
              </div>
              <div class="profile-progress" title="${e.subscriptionUserinfo?c(e.subscriptionUserinfo):"No subscription usage quota"}"><b style="width:${St(e).toFixed(1)}%"></b></div>
            </div>
            <div class="profile-card-primary">
              ${e.sourceUrl?`<button data-update-profile="${c(e.id)}" title="Update subscription">\u27F3</button>`:`<button data-profile-action="edit" data-profile-id="${c(e.id)}" title="Edit local profile">\u2039\u203A</button>`}
            </div>
          </article>
        `).join(""):`
          <div class="empty-profile-state">
            <p>No profiles found in the managed profiles directory.</p>
            <button data-action="migrate-legacy-profiles">Import CFW Profiles</button>
          </div>
        `}
      </section>
      ${Lt()}
    </div>
  `}function Lt(){let e=s.profileInspector;if(!e)return"";let t=e.profile??{},a=`${t.name??e.id} \xB7 ${e.mode}`,o=t.source_url??t.sourceUrl??null,r=t.body?[...t.body.matchAll(/^([A-Za-z0-9_-]+):/gm)].map(l=>l[1]).filter(l=>l.toLowerCase().includes("parser")):[],n="";return e.mode==="diff"?n=`
      <div class="profile-diff-grid">
        <div><p class="label">Managed YAML</p><pre>${c(t.body??"")}</pre></div>
        <div><p class="label">Generated config.yaml preview</p><pre>${c(t.generated_body??"")}</pre></div>
      </div>
    `:e.mode==="edit"?n=`
      <textarea class="profile-editor" data-profile-editor spellcheck="false">${c(t.body??"")}</textarea>
      <div class="row-actions">
        <button class="button" data-action="save-profile-editor">Save YAML</button>
        <button class="button ghost" data-action="close-profile-inspector">Close</button>
      </div>
    `:e.mode==="qrcode"?n=e.svg?`<div class="profile-qr">${e.svg}</div><p class="muted">${c(o??"")}</p>`:`<p class="empty">${c(e.error??"This local profile has no subscription URL.")}</p>`:e.mode==="parsers"?n=`
      <dl class="detail-grid">
        <div><dt>Parser keys</dt><dd>${r.length?r.map(c).join(", "):"none in this profile"}</dd></div>
        <div><dt>Execution</dt><dd>Parser scripts are treated as config transformation metadata only; arbitrary script execution is not enabled from the dashboard.</dd></div>
      </dl>
    `:n=`
      <dl class="detail-grid">
        <div><dt>ID</dt><dd>${c(t.id??e.id)}</dd></div>
        <div><dt>Path</dt><dd>${c(t.path??"")}</dd></div>
        <div><dt>Active</dt><dd>${t.active?"yes":"no"}</dd></div>
        <div><dt>Source URL</dt><dd>${c(o??"local file")}</dd></div>
      </dl>
    `,`
    <section class="panel profile-inspector">
      <div class="section-heading">
        <div>
          <p class="label">Profile Inspector</p>
          <h3>${c(a)}</h3>
        </div>
        <button class="button ghost" data-action="close-profile-inspector">Close</button>
      </div>
      ${n}
    </section>
  `}function At(){let e=s.providerBulkActions.has("update-all-providers"),t=s.providerBulkActions.has("health-check-all");return`
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
        ${s.providers.length?s.providers.map(a=>{let o=W("proxy-update",a.name),r=W("proxy-health",a.name),n=s.providerActions.has(o),l=s.providerActions.has(r);return`
            <article class="panel provider-row">
              <div>
                <p class="label">${c(a.vehicle)}</p>
                <h3>${c(a.name)}</h3>
                <p class="muted">${a.proxies} proxies \xB7 ${c(a.health)} \xB7 updated ${c(a.updated)}</p>
              </div>
              <div class="row-actions">
                <button class="button ghost" data-provider-update="${c(a.name)}" ${n?"disabled":""}>${n?"Updating":"Update"}</button>
                <button class="button" data-provider-health="${c(a.name)}" ${l?"disabled":""}>${l?"Checking":"Health Check"}</button>
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
        ${s.ruleProviders.length?s.ruleProviders.map(a=>{let o=W("rule-update",a.name),r=s.providerActions.has(o);return`
            <article class="panel provider-row">
              <div>
                <p class="label">${c(a.behavior)}</p>
                <h3>${c(a.name)}</h3>
                <p class="muted">${a.rules.toLocaleString()} rules \xB7 updated ${c(a.updated)}</p>
              </div>
              <div class="row-actions">
                <button class="button ghost" data-rule-provider-update="${c(a.name)}" ${r?"disabled":""}>${r?"Updating":"Update"}</button>
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
  `}function Et(){return`
    <div class="logs-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">Diagnostics</p>
          <h3>${ke().length} log entries${s.logsPaused?" paused":""}</h3>
        </div>
        <div class="search-box">
          <input value="${c(s.logSearch)}" data-log-search aria-label="Search logs" placeholder="Search logs or regex" />
        </div>
        <div class="segmented" data-log-filters>
          ${["all","info","debug","warning","error"].map(t=>`
            <button type="button" class="${s.logFilter===t?"selected":""}" data-log-filter="${t}">${t.toUpperCase()}</button>
          `).join("")}
        </div>
        <div class="toolbar-actions">
          <button type="button" class="button ghost" data-action="toggle-log-stream">${s.logsPaused?"Start":"Stop"}</button>
          <button type="button" class="button ghost" data-action="copy-logs">Copy</button>
          <button type="button" class="button ghost" data-action="reveal-logs">Open Folder</button>
          <button type="button" class="button ghost" data-action="clear-logs">Clear</button>
        </div>
      </section>

      <section class="panel log-stream">
        ${Fe()}
      </section>
    </div>
  `}function Tt(e){let t=e.metadata?.processPath??e.metadata?.process_path??e.processPath??"";if(!t)return"\u2014";let a=String(t).split(/[/\\]/).filter(Boolean);return a[a.length-1]||String(t)}function Je(e,t){return`
    <article class="cfw-conn-item${t?" with-process":""}" data-connection-id="${c(e.id)}">
      <div class="conn-main">
        <h3>${c(e.host)}</h3>
        <div class="conn-chips">
          <span class="conn1">${c(e.rule||"MATCH")}</span>
          ${(e.chains??[]).slice(0,4).map((a,o)=>`<span class="conn${o%6+2}">${c(a)}</span>`).join("")}
          <span class="conn7">${c(e.metadata?.network??e.metadata?.type??"tcp")}</span>
        </div>
      </div>
      ${t?`<div class="conn-process" title="${c(e.metadata?.processPath??e.metadata?.process_path??"")}">${c(Tt(e))}</div>`:""}
      <div class="conn-traffic">
        <b data-conn-up>\u2191 ${c(e.upload)}</b>
        <b data-conn-down>\u2193 ${c(e.download)}</b>
        <small data-conn-speed>${c(e.speed??"0 B/s")}</small>
      </div>
      <div class="conn-actions">
        <button data-connection-detail="${c(e.id)}">Info</button>
        <button data-close-connection="${c(e.id)}" ${s.closingConnectionIds.has(e.id)?"disabled":""}>${s.closingConnectionIds.has(e.id)?"Closing":"Close"}</button>
      </div>
    </article>
  `}function Dt(){let e=He(),t=s.connections.find(n=>n.id===s.connectionDetailId),a=S(s.connectionStream.uploadTotal),o=S(s.connectionStream.downloadTotal),r=s.toggles.showProcess!==!1;return w.connectionRowEls=null,`
    <div class="connections-layout" data-connections-root>
      <section class="cfw-conn-header">
        <h1>Connections</h1>
        <div class="cfw-conn-search">
          <span>\u25CF</span>
          <input value="${c(s.connectionSearch)}" data-connection-search aria-label="Search connections" placeholder="Search connections" />
          ${s.connectionSearch?'<button data-action="clear-connection-search">\xD7</button>':""}
        </div>
        <strong data-conn-totals>Total: \u2191 ${a} \u2193 ${o}</strong>
      </section>

      <section class="cfw-conn-controls">
        ${[["upload","\u21A5 \u25D2"],["download","\u21A7 \u25D2"],["upload","\u21A5 \u25A5"],["download","\u21A7 \u25A5"],["age","\u25F7"],["host","\u25AD"]].map(([n,l])=>`
          <button class="${s.connectionSort===n?"selected":""}" data-connection-sort="${n}">${l}</button>
        `).join("")}
        <span></span>
        <button class="danger" data-action="toggle-connection-stream">${s.connectionPaused?"Resume":"Pause"}</button>
        <button class="danger" data-action="close-all" data-conn-close-all ${s.closingAllConnections?"disabled":""}>${s.closingAllConnections?"Closing...":`Close All (${e.length})`}</button>
      </section>

      <section class="cfw-conn-scroll" data-conn-scroll>
        ${e.map(n=>Je(n,r)).join("")}
      </section>
      ${t?Ze(t):""}
    </div>
  `}function Rt(){let e=document.querySelector("[data-connections-root]"),t=document.querySelector("[data-conn-scroll]");if(!e||!t||s.activePage!=="connections"){h();return}let a=He(),o=s.toggles.showProcess!==!1,r=e.querySelector("[data-conn-totals]");r&&(r.textContent=`Total: \u2191 ${S(s.connectionStream.uploadTotal)} \u2193 ${S(s.connectionStream.downloadTotal)}`);let n=e.querySelector("[data-conn-close-all]");n&&(n.disabled=!!s.closingAllConnections,n.textContent=s.closingAllConnections?"Closing...":`Close All (${a.length})`),w.connectionRowEls instanceof Map||(w.connectionRowEls=new Map,t.querySelectorAll("[data-connection-id]").forEach(m=>{w.connectionRowEls.set(m.getAttribute("data-connection-id"),m)}));let l=new Set(a.map(m=>m.id));for(let[m,C]of[...w.connectionRowEls.entries()])l.has(m)||(C.remove(),w.connectionRowEls.delete(m));let d=document.createDocumentFragment(),u=!1;a.forEach((m,C)=>{let $=w.connectionRowEls.get(m.id);if(!$){let Z=document.createElement("div");Z.innerHTML=Je(m,o).trim(),$=Z.firstElementChild,w.connectionRowEls.set(m.id,$),u=!0,d.appendChild($);return}let q=$.querySelector("[data-conn-up]"),R=$.querySelector("[data-conn-down]"),U=$.querySelector("[data-conn-speed]");q&&(q.textContent=`\u2191 ${m.upload}`),R&&(R.textContent=`\u2193 ${m.download}`),U&&(U.textContent=m.speed??"0 B/s");let J=$.querySelector("[data-close-connection]");if(J){let Z=s.closingConnectionIds.has(m.id);J.disabled=Z,J.textContent=Z?"Closing":"Close"}let j=t.children[C];!u&&j!==$&&t.insertBefore($,j??null)}),d.childNodes.length&&t.appendChild(d);let g=s.connections.find(m=>m.id===s.connectionDetailId),f=e.querySelector(".modal-backdrop");g&&!f?(e.insertAdjacentHTML("beforeend",Ze(g)),et()):!g&&f&&f.remove()}function It(){w.connectionsPatchFrame===null&&(w.connectionsPatchFrame=window.requestAnimationFrame(()=>{w.connectionsPatchFrame=null,Rt()}))}function Ze(e){let t=e.metadata??{};return`
    <div class="modal-backdrop" data-action="close-connection-detail">
      <section class="connection-info-modal" data-modal-stop>
        <div class="modal-head">
          <h2>Connection Info</h2>
          <button data-action="close-connection-detail">\xD7</button>
        </div>
        <dl>
          ${[["Host",e.host],["Rule",e.rule],["Chains",(e.chains??[]).join(" / ")],["Upload",e.upload],["Download",e.download],["Speed",e.speed],...Object.entries(t).filter(([,o])=>o!=null&&o!=="")].map(([o,r])=>`
            <div>
              <dt>${c(o)}</dt>
              <dd>${c(String(r??""))}</dd>
              <button data-copy-text="${c(String(r??""))}">Copy</button>
            </div>
          `).join("")}
        </dl>
      </section>
    </div>
  `}function Bt(){let e=rt();return`
    <div class="rules-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">Router</p>
          <h3>${e.length} / ${s.rules.length} active rule entries</h3>
          <p class="muted">Live data from Clash controller /rules, including rule type, payload, proxy target and hit counters when exposed by the core.</p>
        </div>
        <div class="search-box">
          <input value="${c(s.ruleSearch)}" data-rule-search aria-label="Search rules" placeholder="Search rules" />
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
              <span>${c(t.index)}</span>
              <span>${c(t.type)}</span>
              <span>${c(t.payload||"-")}</span>
              <span>${c(t.proxy)}</span>
              <span>${c(t.hits)}</span>
            </div>
          `).join("")||'<p class="empty">No rules loaded from the controller.</p>'}
        </div>
      </section>
    </div>
  `}function F(e,t){return`
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">Settings</p>
          <h3>${c(e)}</h3>
        </div>
      </div>
      <div class="settings-list">${t.join("")}</div>
    </section>
  `}function qt(){let e=s.networkDiagnostics;if(!e)return F("Network Diagnostics",[b("Default Route","Unavailable","Run inside the Tauri app to inspect macOS service order.")]);let t=e.services??[],a=e.recommended_clash_proxy_services??[],o=[b("Default Route",e.default_route_interface??"unknown","BSD interface used by the active default route."),b("Proxy Target",a.length?a.join(", "):"fallback to active services","System Proxy now prefers the default-route service before touching other services.")];return o.push(...t.map(r=>{let n=[r.proxy?.web,r.proxy?.secure_web,r.proxy?.socks].filter(Boolean),l=n.some(m=>m.managed_by_clash),d=!l&&n.some(m=>m.enabled),u=l?"Clash":d?"External":"Off",g=[r.hardware_port,r.bsd_device].filter(Boolean).join(" / ")||r.service_type||"unknown",f=r.is_default_route?"default route":`order ${r.service_order??"-"}`;return b(r.service,`${u} \xB7 ${g}`,`${f}; bypass ${r.bypass_domains?.length??0} domain(s).`)})),F("Network Diagnostics",o)}function Ut(){return`
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">Mixin</p>
          <h3>YAML Merge Before Apply</h3>
          <p class="muted">When Mixin is enabled, this YAML mapping is recursively merged into generated config.yaml before the core reloads.</p>
        </div>
        ${L("mixin","Mixin","Enable runtime YAML merge.")}
      </div>
      <textarea class="mixin-editor" data-mixin-yaml spellcheck="false" placeholder="dns:
  enable: true
profile:
  store-selected: true">${c(s.mixinYaml??"")}</textarea>
    </section>
  `}function Nt(){return`
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">Profile Parser</p>
          <h3>Safe Parser Script Before Mixin</h3>
          <p class="muted">Runs when previewing or applying profiles. Supported commands: set, delete, append, prepend, append-rule, prepend-rule, merge.</p>
        </div>
        <span class="badge">raw \u2192 parser \u2192 mixin \u2192 runtime</span>
      </div>
      <textarea class="mixin-editor" data-profile-parser-script spellcheck="false" placeholder="prepend-rule DOMAIN-SUFFIX,example.com,DIRECT&#10;set dns.enable true&#10;delete proxy-providers">${c(s.profileParserScript??"")}</textarea>
    </section>
  `}function Ft(){return`
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
      ${ae("Tray Script",s.trayScript,"/usr/bin/say 'Clash for Mac'","Absolute executable path plus arguments; shell expansion is intentionally disabled.","data-tray-script")}
      ${ae("Child Process",s.childProcessCommand,"/usr/bin/env","Lifecycle command staged for helper/service mode experiments.","data-child-process-command")}
    </section>
  `}function Ht(){let e=s.payload.product??T.product,t=s.updateInfo,a=t?.available&&t?.version?`New version available: v${c(String(t.version))} (current v${c(String(t.current??e.version??"0.3.4"))}).`:`Current build v${c(e.version??"0.3.4")} \u2014 menu bar Clash for Mac \u2192 Check for Update\u2026 also works.`,o=s.kernelCompare?.comparison,r=o?`<p class="muted">${c(o.narrative?.speed??"")}</p>
       <p class="muted">${c(o.narrative?.stability??"")}</p>
       <p class="muted">${c(o.narrative?.weak_net??"")}</p>
       <p class="muted">Measured ${c(String(s.kernelCompare.measured_at??"local"))}. Not a CFW 3\xD7 claim.</p>`:'<p class="muted">Measured report not loaded yet.</p>';return`
    <div class="feedback-layout">
      <section class="panel hero-panel">
        <div>
          <p class="label">Feedback</p>
          <h3>${c(e.name)} v${c(e.version??"0.3.4")}${t?.available&&t?.version?` \u2192 v${c(String(t.version))}`:""}</h3>
          <p class="muted">Parity target is CFW 0.20.39; this build is the Apple Silicon beta (${c(e.version??"0.3.4")}).</p>
        </div>
        <span class="badge">ARM64 macOS only</span>
      </section>

      <section class="panel">
        <p class="label">Updates</p>
        <h3>Check for Updates</h3>
        <p class="muted">${a}</p>
        <div class="toolbar-actions">
          <button class="button" data-action="check-for-updates">Check for Updates</button>
        </div>
      </section>

      <section class="panel">
        <p class="label">Measured</p>
        <h3>clash-rs vs mihomo</h3>
        ${r}
        <div class="toolbar-actions">
          <button class="button ghost" data-action="show-kernel-compare">Show Bench Details</button>
        </div>
      </section>

      <section class="panel">
        <p class="label">Parity source</p>
        <h3>CFW 0.20.39 (reference)</h3>
        <p class="muted">${c(e.parity_source??"reverse artifact")}</p>
        <dl class="ports-list feedback-list">
          <div><dt>main</dt><dd>reverse/cfw-0.20.39-arm64/asar/main.js</dd></div>
          <div><dt>renderer</dt><dd>reverse/cfw-0.20.39-arm64/asar/renderer.js</dd></div>
          <div><dt>window</dt><dd>850 x 603 min frameless baseline</dd></div>
          <div><dt>routes</dt><dd>general / proxy / provider / log / server / connection / router / setting / about</dd></div>
        </dl>
      </section>
    </div>
  `}function b(e,t,a){return`
    <div class="setting-row">
      <span>
        <b>${c(e)}</b>
        <small>${c(a)}</small>
      </span>
      <strong>${c(t)}</strong>
    </div>
  `}function ae(e,t,a,o,r){return`
    <label class="setting-row setting-control-row">
      <span>
        <b>${c(e)}</b>
        <small>${c(o)}</small>
      </span>
      <input class="setting-input" ${r} value="${c(t??"")}" placeholder="${c(a??"")}" />
    </label>
  `}function zt(e,t,a,o,r){return`
    <label class="setting-row setting-control-row">
      <span>
        <b>${c(e)}</b>
        <small>${c(o)}</small>
      </span>
      <select class="setting-input" ${r}>
        ${a.map(n=>`<option value="${c(n.value)}" ${n.value===t?"selected":""}>${c(n.label)}</option>`).join("")}
      </select>
    </label>
  `}function ge(e,t,a,o,r){return`
    <div class="setting-row">
      <span>
        <b>${c(e)}</b>
        <small>${c(a)}</small>
      </span>
      <span class="setting-action">
        <strong>${c(t)}</strong>
        <button class="button ghost" data-action="${c(o)}">${c(r)}</button>
      </span>
    </div>
  `}function Ot(){let e=s.payload.quality??T.quality,t=e.performance,a=e.stability;return`
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
  `}function Gt(){let e=s.payload.platform??T.platform,t=s.settingsSnapshot??y,a=t.settings??y.settings,o=t.paths??y.paths,r=`${a.external_controller_host}:${a.external_controller_port}`,n=a["interface-name"]??a.interfaceName??"",l=s.networkDiagnostics?.default_route_interface??"auto",d=a.theme==="dark"?"dark":"light",u=a.font_family??a.fontFamily??"",g=[["Security",[b("Core Secret",a.secret?"random UUID":"not set","Protect Clash REST API with a random RFC4122 UUID.")]],["Appearance",[zt("Theme",d,[{value:"light",label:"Light"},{value:"dark",label:"Dark"}],"Persisted app theme applied at boot.","data-theme-setting"),ae("Font",u,"Avenir Next","Override dashboard font family; blank uses the CFW-like default.","data-font-family")]],["System Proxy",[L("systemProxy","System Proxy","Enable macOS system HTTP/HTTPS/SOCKS proxy."),L("proxyDelayIndicator","Tray delay indicator","Show selected-node latency in the menu-bar title/tooltip."),L("usePacScript","Use PAC Script","When System Proxy is on, apply Auto Proxy URL (PAC) instead of manual HTTP/HTTPS/SOCKS."),(()=>{let m=(a.proxy_bypass??[]).join(`
`),C=a.pacScript??a.pac_script??s.pacScript??"";return`
          <label class="setting-row setting-control-row">
            <span>
              <b>Bypass Domains</b>
              <small>One host or CIDR per line. Empty uses the built-in LAN/localhost defaults. Applied when System Proxy turns on (manual mode).</small>
            </span>
            <textarea class="mixin-editor" data-proxy-bypass spellcheck="false" rows="5">${c(m)}</textarea>
          </label>
          <label class="setting-row setting-control-row">
            <span>
              <b>PAC Script</b>
              <small>FindProxyForURL body. Empty generates PROXY/SOCKS5 for the current mixed-port. Written to app-home proxy.pac when Use PAC Script is on.</small>
            </span>
            <textarea class="mixin-editor" data-pac-script spellcheck="false" rows="8" placeholder="function FindProxyForURL(url, host) {&#10;  return &quot;PROXY 127.0.0.1:7890; SOCKS5 127.0.0.1:7890; DIRECT&quot;;&#10;}">${c(C)}</textarea>
          </label>`})()]],["Mixin",[L("mixin","Mixin","Merge YAML/JS mixin before profile apply."),b("Mixin YAML","Editor active","The YAML merge editor below is persisted and applied before config reload.")]],["Proxies",[L("hideUnavailable","Hide timed-out proxies","Hide nodes that failed latency tests (Timeout), matching CFW Show/Hide timed-out proxies."),ae("Delay test URL",a.delayTestUrl??a.delay_test_url??"http://www.gstatic.com/generate_204","http://www.gstatic.com/generate_204","Used by Proxies \u2192 Delay Test against the live controller.","data-delay-test-url")]],["Connections",[L("breakOnProxyChange","Break connections","Disconnect sockets after proxy or profile changes."),L("showProcess","Show Process","Show connection process name from metadata.processPath when the core reports it.")]],["Providers",[b("Use CFW Editor","Profile editor active","Profile YAML edit/diff is built in; provider file editor remains behind controller metadata."),b("Update All","Controller-backed","Proxy and rule providers expose bulk update actions.")]],["Outbound",[ae("Interface Name",n,l,"Bind Clash outbound sockets to a macOS BSD interface; blank keeps Clash automatic.","data-outbound-interface")]],["Child Processes",[b("Processes","Action runner","Spawn child processes through a typed Rust command boundary.")]],["Profiles",[b("Parsers","Safe script active","Apply parser scripts before mixin/runtime config generation."),b("Headers","Captured","Remote imports persist subscription-userinfo and profile-update-interval metadata.")]],["Logs",[b("Request Logs","Preload + stream","Original supports log preload, filters and log-level changes.")]],["SSID",[b("SSID Policy","Not in 0.2.0","CFW could vary proxy/profile by Wi-Fi SSID. Deferred \u2014 this toggle is intentionally unavailable.")]],["Actions",[b("Tray Script","Rust action runner","Run Tray Script action is executable from settings and tray.")]],["Shortcuts",[b("Mode shortcuts","Active","Cmd+1..6, Cmd+G/R/D/S/P/T/M mirror original dashboard shortcuts.")]],["CFW Editor",[b("Diff Editor","Not in 0.2.0","Built-in YAML edit exists on Profiles; Monaco-style side-by-side diff is deferred.")]],["Cache",[ge("Fake IP Cache","Controller-backed","Flush Mihomo fake-ip cache through /cache/fakeip/flush.","flush-fake-ip-cache","Flush")]],["Experimental Features",[b("DHCP Server","Not in 0.2.0","CFW macOS DHCP server switch is not shipped in this beta."),L("enableIpv6","IPv6","Expose IPv6 option in generated Clash config.")]]],f=ee(s.serviceModeStatus);return`
    <div class="settings-layout">
      <section class="panel toolbar-panel settings-toolbar">
        <div>
          <p class="label">Settings Store</p>
          <h3>${t.persisted?"cfw-settings.yaml loaded":"Defaults staged"}</h3>
          <p class="muted">${c(o.settings_file)}${t.persisted?"":" will be created on save."}</p>
        </div>
        <div class="toolbar-actions">
          <button class="button ghost danger" data-action="reset-settings">Reset All Settings</button>
          <button class="button" data-action="save-settings">Save Settings</button>
          <button class="button ghost" data-action="reload-settings">Reload From Disk</button>
          <button class="button ghost" data-action="force-quit-app">Force Quit</button>
          <button class="button ghost" data-action="quit-app">Quit</button>
        </div>
      </section>
      ${F("General",[L("startAtLogin","Start at Login","Launch Clash for Mac after login via SMAppService Login Item."),L("silentStart","Silent Start","Start hidden in tray without Dock bounce (Accessory policy)."),L("proxyDelayIndicator","Tray delay indicator","Show current proxy latency in tray quick menu."),ge("Updates","GitHub Releases","Check tauri-plugin-updater against the latest signed release.","check-for-updates","Check for Updates")])}
      ${F("Core",[b("mixed-port",String(a.mixed_port),"HTTP, HTTPS and SOCKS entry point."),b("external-controller",r,"Local Clash controller endpoint."),b("secret",a.secret?"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022":"empty","Controller secret stored in cfw-settings.yaml."),`
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
        `,L("enableIpv6","IPv6","Expose IPv6 option in generated Clash config."),ge("Install clash-rs","Apple Silicon only","Download pinned clash-rs v0.10.7 beside mihomo (does not change default).","install-pinned-clash-rs","Install")])}
      ${Ut()}
      ${Nt()}
      ${Ft()}
      ${F("Paths",[b("Home Directory",o.app_home,"macOS application support root."),b("Settings",o.settings_file,"Clash for Mac shell settings."),b("Profiles",o.profiles_dir,"Imported and generated profile files."),b("Logs",o.logs_dir,"Core, shell and helper logs."),b("Cores",o.cores_dir,"Apple Silicon Clash core binaries."),b("Helpers",o.helpers_dir,"Privileged helper payload staging.")])}
      ${F("macOS",[b("Minimum macOS",e.minimum_macos??"13.0","ARM64-only app baseline."),b("Intel support",e.intel_supported?"Enabled":"Disabled","Removed to optimize Apple Silicon runtime."),b("System proxy",e.system_proxy_strategy??"native manager","Rust SystemConfiguration boundary."),b("Service Mode",f,"Live SMAppService status for the privileged helper."),ge("Service Mode",f,"Register the SMAppService helper (approve under Login Items if prompted).","manage-service-mode","Manage")])}
      ${qt()}
      ${F("Experimental",[L("hideUnavailable","Hide timed-out proxies","Hide nodes that failed latency tests (Timeout)."),b("TUN",e.tun_strategy??"SmAppServiceRootHelper","Production TUN path: SMAppService root helper (not Network Extension)."),b("UI shell","Tauri 2 + WebKit","Native Tauri shell. React is not the product UI."),b("launchd",e.launchd_strategy??"typed launchd contract","No product-layer ad-hoc scripts.")])}
      <section class="panel settings-index">
        <div class="section-heading">
          <div>
            <p class="label">Original Settings Taxonomy</p>
            <h3>CFW Setting Groups</h3>
          </div>
          <span class="badge">${g.length} groups</span>
        </div>
        <div class="settings-taxonomy">
          ${g.map(([m,C])=>`
            <article class="taxonomy-group">
              <h4>${c(m)}</h4>
              ${C.join("")}
            </article>
          `).join("")}
        </div>
      </section>
      ${Ot()}
      <section class="panel deep-link-panel">
        <div class="section-heading">
          <div>
            <p class="label">clash:// protocol</p>
            <h3>Deep link events</h3>
          </div>
          <button class="button ghost" data-action="clear-deep-links">Clear</button>
        </div>
        <pre>${s.deepLinks.length?c(JSON.stringify(s.deepLinks,null,2)):"No deep links received yet."}</pre>
      </section>
    </div>
  `}var jt={general:We,proxies:ft,profiles:Mt,providers:At,logs:Et,connections:Dt,rules:Bt,settings:Gt,feedback:Ht};function h(){let e=Se(s.activePage);document.title="";let t=document.getElementById("product-name");t&&(t.textContent=s.payload.product?.name??"Clash for Mac");let a=document.getElementById("status-title");a&&(a.textContent=`${e.title} - ${s.mode} Mode`),document.getElementById("page-title").textContent=e.title,document.getElementById("page-summary").textContent=e.summary;let o=s.coreStatus?.state==="Running",r=document.getElementById("sidebar-status");r&&(r.textContent=o?"Connected":"Disconnected");let n=document.getElementById("sidebar-status-dot");n&&(n.className=o?"on":""),H(),nt(),document.getElementById("page").innerHTML=(jt[s.activePage]??We)(),et(),_(),s.profileInspector?.mode==="edit"&&s.profileInspector.focusKey&&requestAnimationFrame(()=>Kt(s.profileInspector.focusKey))}function H(){let e=document.getElementById("upload-rate"),t=document.getElementById("download-rate"),a=document.getElementById("runtime-value"),o=document.getElementById("traffic-progress");if(e&&(e.textContent=_e(s.traffic.upload)),t&&(t.textContent=_e(s.traffic.download)),a&&(a.textContent=Ae(s.traffic.runtimeSeconds)),o){let r=Math.min(100,Math.max(0,(s.traffic.upload+s.traffic.download)*4));o.style.width=`${r}%`}}function se(){w.renderFrame===null&&(w.renderFrame=window.requestAnimationFrame(()=>{w.renderFrame=null,w.connectionRowEls=null,h()}))}async function $e(e){let t=s.profiles.find(r=>r.id===e);if(!t)throw new Error(`profile not found: ${e}`);if(t.active)return i("info","profile",`${t.name} is already active`),!1;let a=P().active?P().id:null,o=await p("write_settings_snapshot",{settings:{...x(),active_profile:e}});v(o),await k();try{let r=await p("apply_active_profile");return i("info","profile",`Profile switched to ${P().name}; config.yaml updated (${S(r.bytes??0)})`),await G(s.toggles.tunMode?10:6,500),s.toggles.breakOnProxyChange&&await oe("profile"),!0}catch(r){let n=await p("write_settings_snapshot",{settings:{...x(),active_profile:a}});if(v(n),await k(),a)try{await p("apply_active_profile")}catch(l){i("warning","profile",`Rollback re-apply failed: ${l.message??String(l)}`)}throw await G(6,400).catch(()=>!1),i("error","profile",`Could not switch to ${t.name}: ${r.message??String(r)}`),r}}function et(){document.querySelectorAll("[data-toggle]").forEach(n=>{n.addEventListener("change",async l=>{let d=l.currentTarget.dataset.toggle,u=l.currentTarget.checked;try{await z(d,u,"ui")}catch(g){i("warning","ui",`${d} refused: ${g.message??String(g)}`)}h()})}),document.querySelectorAll("[data-log-level]").forEach(n=>{n.addEventListener("change",async l=>{let d=s.logLevel;s.logLevel=l.currentTarget.value;try{let u=await p("write_settings_snapshot",{settings:x()});v(u);try{await p("set_log_level",{level:s.logLevel}),i("info","settings",`Clash log level applied: ${s.logLevel}`)}catch(g){s.controllerStatus="controller offline",i("warning","settings",`Log level saved; controller apply failed: ${g.message??String(g)}`)}}catch(u){s.logLevel=d,i("error","settings",`Log level refused: ${u.message??String(u)}`)}h()})}),document.querySelectorAll("[data-mixed-port]").forEach(n=>{n.addEventListener("change",()=>{O("save-mixed-port").catch(l=>{i("error","settings",l.message??String(l)),h()})}),n.addEventListener("keydown",l=>{l.key==="Enter"&&l.currentTarget.blur()})}),document.querySelectorAll("[data-random-mixed-port]").forEach(n=>{n.addEventListener("change",async l=>{try{let d=await p("write_settings_snapshot",{settings:{...x(),randomMixedPort:l.currentTarget.checked}});v(d),i("info","settings",`Random mixed-port ${l.currentTarget.checked?"enabled":"disabled"}`)}catch(d){i("error","settings",`Random mixed-port refused: ${d.message??String(d)}`)}h()})}),document.querySelectorAll("[data-core-kind]").forEach(n=>{n.addEventListener("change",async l=>{let d=l.currentTarget.value||"mihomo";try{let u=await p("write_settings_snapshot",{settings:{...x(),coreKind:d,core_kind:d}});v(u),i("info","core",d==="mihomo"?"Preferred core set to mihomo (manual override)":"Preferred core set to clash-rs (default)")}catch(u){i("error","settings",`Core kind refused: ${u.message??String(u)}`)}h()})});let e=document.querySelector("[data-proxy-filter]");e&&e.addEventListener("input",n=>{s.proxyFilter=n.currentTarget.value,h()}),document.querySelectorAll("[data-collapse-group]").forEach(n=>{n.addEventListener("click",l=>{let d=l.currentTarget.dataset.collapseGroup;s.collapsedProxyGroups.has(d)?s.collapsedProxyGroups.delete(d):s.collapsedProxyGroups.add(d),h()})}),document.querySelectorAll("[data-scroll-group]").forEach(n=>{n.addEventListener("click",l=>{let d=l.currentTarget.dataset.scrollGroup;document.getElementById(`proxy-group-${ut(d)}`)?.scrollIntoView({block:"start",behavior:"smooth"})})}),document.querySelectorAll("[data-proxy-group-tab]").forEach(n=>{n.addEventListener("click",l=>{ve(),s.activeProxyGroup=l.currentTarget.dataset.proxyGroupTab,h()})});let t=document.querySelector("[data-profile-file]");t&&t.addEventListener("change",()=>{O("import-profile-file").catch(n=>{i("error","profile",n.message??String(n)),h()})}),document.querySelectorAll("[data-page]").forEach(n=>{n.addEventListener("click",async l=>{let d=l.currentTarget.dataset.page;d!=="proxies"&&ve(),s.activePage=d,await p("open_page",{page:d}),h(),d==="proxies"&&(await G(6,400),h()),d==="rules"&&(await we(),h())})}),document.querySelectorAll("[data-mode]").forEach(n=>{n.addEventListener("click",async l=>{let d=s.mode;s.mode=l.currentTarget.dataset.mode;try{await p("set_proxy_mode",{mode:s.mode});let u=await p("write_settings_snapshot",{settings:x()});v(u),i("info","mode",`Proxy mode switched to ${s.mode}`),s.toggles.breakOnProxyChange&&await oe("mode")}catch(u){s.mode=d,s.controllerStatus="controller offline",i("warning","mode",`Proxy mode refused by controller: ${u.message??String(u)}`)}h()})}),document.querySelectorAll("[data-group][data-node]").forEach(n=>{n.addEventListener("click",async l=>{let d=s.proxyGroups.find(g=>g.name===l.currentTarget.dataset.group);if(!d)return;let u=d.now;d.now=l.currentTarget.dataset.node;try{await p("select_proxy",{group:d.name,proxy:d.now}),i("info","proxy",`Proxy group ${d.name} switched to ${d.now}`),s.toggles.breakOnProxyChange&&await oe(d.name)}catch(g){d.now=u,s.controllerStatus="controller offline",i("warning","proxy",`Proxy selection refused: ${g.message??String(g)}`)}h()})}),document.querySelectorAll("[data-profile]").forEach(n=>{n.addEventListener("click",async l=>{l.preventDefault(),l.stopPropagation();let d=l.currentTarget.dataset.profile;try{await $e(d)}catch(u){i("error","profile",`Profile switch failed: ${u.message??String(u)}`)}h()})}),document.querySelectorAll("[data-update-profile]").forEach(n=>{n.addEventListener("click",async l=>{let d=s.profiles.find(g=>g.id===l.currentTarget.dataset.updateProfile);if(!d)return;if(!d.sourceUrl){i("warning","profile",`${d.name} is a local profile; use Import File again to replace it`),h();return}let u=d.active;try{let g=await p("update_profile",{id:d.id});await k(),u&&await p("apply_active_profile"),i("info","profile",`${g.name} subscription updated${u?" and config.yaml reapplied":""}`)}catch(g){i("error","profile",`Update failed for ${d.name}: ${g.message??String(g)}`)}h()})}),document.querySelectorAll("[data-reveal-profile]").forEach(n=>{n.addEventListener("click",async l=>{let d=l.currentTarget.dataset.revealProfile;try{await p("reveal_profile",{id:d}),i("info","profile",`Profile revealed in Finder: ${d}`)}catch(u){i("warning","profile",`Show in Finder failed: ${u.message??String(u)}`)}h()})}),document.querySelectorAll("[data-delete-profile]").forEach(n=>{n.addEventListener("click",async l=>{let d=l.currentTarget.dataset.deleteProfile;try{await Qe("delete",d)}catch(u){i("error","profile",`Delete failed: ${u.message??String(u)}`)}h()})}),document.querySelectorAll("[data-profile-card]").forEach(n=>{n.addEventListener("click",async l=>{if(l.target.closest("button, a, input, textarea, select"))return;let d=n.dataset.profileCard;if(d){try{await $e(d)}catch{}h()}}),n.addEventListener("contextmenu",l=>{l.preventDefault(),l.stopPropagation(),kt(n.dataset.profileCard,l.clientX,l.clientY)})}),document.querySelectorAll("[data-profile-action]").forEach(n=>{n.addEventListener("click",async l=>{let d=l.currentTarget.dataset.profileAction,u=l.currentTarget.dataset.profileId;try{await B(u,d),i("info","profile",`${d} opened for ${u}`)}catch(g){i("error","profile",`${d} failed for ${u}: ${g.message??String(g)}`)}h()})}),document.querySelectorAll("[data-provider-update], [data-rule-provider-update]").forEach(n=>{n.addEventListener("click",async l=>{let d=l.currentTarget.dataset.providerUpdate,u=l.currentTarget.dataset.ruleProviderUpdate,g=d??u,f=W(d?"proxy-update":"rule-update",g);s.providerActions.add(f),h();try{d?await p("update_proxy_provider",{name:d}):await p("update_rule_provider",{name:u}),await Q(),i("info","provider",`${g} update requested through Clash controller`)}catch(m){s.controllerStatus="controller offline",i("warning","provider",`${g} update failed: ${m.message??String(m)}`)}finally{s.providerActions.delete(f)}h()})}),document.querySelectorAll("[data-provider-health]").forEach(n=>{n.addEventListener("click",async l=>{let d=l.currentTarget.dataset.providerHealth,u=W("proxy-health",d);s.providerActions.add(u),h();try{await p("health_check_proxy_provider",{name:d}),await Q(),i("info","provider",`${d} health check requested through Clash controller`)}catch(g){s.controllerStatus="controller offline",i("warning","provider",`${d} health check failed: ${g.message??String(g)}`)}finally{s.providerActions.delete(u)}h()})});let a=document.querySelector("[data-log-search]");a&&a.addEventListener("input",n=>{s.logSearch=n.currentTarget.value,Ce()});let o=document.querySelector("[data-connection-search]");o&&o.addEventListener("input",n=>{s.connectionSearch=n.currentTarget.value,h()});let r=document.querySelector("[data-rule-search]");r&&r.addEventListener("input",n=>{s.ruleSearch=n.currentTarget.value,h()}),document.querySelectorAll("[data-connection-sort]").forEach(n=>{n.addEventListener("click",l=>{let d=l.currentTarget.dataset.connectionSort;s.connectionSort===d?s.connectionSortDesc=!s.connectionSortDesc:(s.connectionSort=d,s.connectionSortDesc=!1),h()})}),document.querySelectorAll("[data-connection-detail]").forEach(n=>{n.addEventListener("click",l=>{s.connectionDetailId=l.currentTarget.dataset.connectionDetail,h()})}),document.querySelectorAll("[data-modal-stop]").forEach(n=>{n.addEventListener("click",l=>l.stopPropagation())}),document.querySelectorAll("[data-copy-text]").forEach(n=>{n.addEventListener("click",async l=>{let d=l.currentTarget.dataset.copyText??"";try{await navigator.clipboard.writeText(d),i("info","clipboard","Connection field copied")}catch{i("warning","clipboard","Clipboard API refused copy")}h()})}),document.querySelectorAll("[data-connection-facet]").forEach(n=>{n.addEventListener("click",l=>{s.connectionSearch=l.currentTarget.dataset.connectionFacet,h()})}),document.querySelectorAll("[data-close-connection]").forEach(n=>{n.addEventListener("click",async l=>{let d=l.currentTarget.dataset.closeConnection;s.closingConnectionIds.add(d),h();try{await p("close_connection",{id:d}),await X(),i("info","connection",`Connection ${d} closed`)}catch(u){s.controllerStatus="controller offline",i("warning","connection",`Controller close failed for ${d}: ${u.message??String(u)}`)}finally{s.closingConnectionIds.delete(d)}h()})})}function Vt(){w.globalEventsBound||(w.globalEventsBound=!0,document.addEventListener("keydown",e=>{e.key==="Escape"&&(s.profileContextMenu||s.glassDialog)&&(e.preventDefault(),A())}),document.addEventListener("click",e=>{let t=e.target instanceof Element?e.target:e.target?.parentElement,a=t?.closest("[data-log-filter]");if(a){e.preventDefault();let r=a.dataset.logFilter||"all";if(s.logFilter===r)return;s.logFilter=r,document.querySelectorAll("[data-log-filter]").forEach(n=>{n.classList.toggle("selected",n.dataset.logFilter===s.logFilter)}),Ce();return}let o=t?.closest("[data-action]");o&&(e.preventDefault(),e.stopPropagation(),O(o.dataset.action).catch(r=>{i("error","ui",r.message??String(r)),h()}))}),document.addEventListener("keydown",e=>{let t=e.key.toLowerCase();if(!(e.metaKey||e.ctrlKey)||e.altKey)return;let o=e.target,r=o instanceof HTMLInputElement||o instanceof HTMLTextAreaElement||o instanceof HTMLSelectElement||o?.isContentEditable,n={1:"general",2:"proxies",3:"profiles",4:"logs",5:"connections",6:"settings"};if(!r&&n[t]){e.preventDefault(),s.activePage=n[t],i("info","shortcut",`Opened ${Se(s.activePage).title}`),h();return}if(r)return;let l={g:()=>he("mode:Global"),r:()=>he("mode:Rule"),d:()=>he("mode:Direct"),p:()=>z("systemProxy",!s.toggles.systemProxy,"shortcut"),t:()=>z("tunMode",!s.toggles.tunMode,"shortcut"),m:()=>z("mixin",!s.toggles.mixin,"shortcut"),s:()=>O("save-settings")}[t];l&&(e.preventDefault(),l().catch(d=>{i("warning","shortcut",d.message??String(d)),h()}))}))}async function z(e,t,a){let o=s.toggles[e];s.toggles[e]=t;try{if(e==="systemProxy"){let r=await p("set_system_proxy_enabled",{enabled:t});v(r),await ye(),await re()}else if(e==="tunMode"){if(t&&s.serviceModeStatus!=="Enabled"){s.toggles[e]=o,s.glassDialog={kind:"info",payload:{title:"TUN Mode",body:"To enable this mode, please install Service Mode first!"}},_();return}let r=await p("set_tun_enabled",{enabled:t});v(r),await ye(),await be(),await G(t?12:6,500)}else if(e==="mixin"){let r=await p("write_settings_snapshot",{settings:{...x(),mixin:t}});if(v(r),P().active){let n=await p("apply_active_profile");i("info",a,`Mixin ${t?"enabled":"disabled"}; active config reapplied (${S(n.bytes??0)})`)}}else if(e==="startAtLogin"){let r=await p("set_launch_at_login_enabled",{enabled:t});v(r)}else if(e==="allowLan"){let r=await p("set_allow_lan",{enabled:t});v(r)}else if(e==="enableIpv6"){let r=await p("set_ipv6",{enabled:t});v(r)}else{let r=await p("write_settings_snapshot",{settings:x()});if(v(r),e==="usePacScript"&&s.toggles.systemProxy){let n=await p("set_system_proxy_enabled",{enabled:!0});v(n),await re()}}i("info",a,`${e} changed to ${t?"on":"off"}`)}catch(r){if(s.toggles[e]=o,e==="tunMode")try{await ne()}catch{}throw r}}async function O(e){if(e==="open-settings"&&(s.activePage="settings"),e==="scroll-to-selected-proxy"){let a=(s.proxyGroups.find(o=>o.name===s.activeProxyGroup)??s.proxyGroups[0])?.now;if(!a){i("warning","proxy","No selected proxy to scroll to");return}s.toggles.showProxiesList=!0,s.proxyBlinkNode=a,h(),requestAnimationFrame(()=>{document.querySelector(`[data-proxy-node="${CSS.escape(a)}"]`)?.scrollIntoView({block:"center",behavior:"smooth"})}),setTimeout(()=>{s.proxyBlinkNode===a&&(s.proxyBlinkNode=null,s.activePage==="proxies"&&h())},1200)}if((e==="toggle-hide-timed-out"||e==="toggle-hide-unavailable")&&(s.toggles.hideUnavailable=!s.toggles.hideUnavailable),e==="toggle-show-proxies"&&(s.toggles.showProxiesList=s.toggles.showProxiesList===!1),e==="toggle-proxy-filter"&&(s.toggles.showProxyFilter=!s.toggles.showProxyFilter,s.toggles.showProxyFilter||(s.proxyFilter="")),e==="break-proxy-connections"){let t=s.connections.length;try{await p("close_all_connections"),i("warning","proxy",`Broke ${t} connection(s)`),await X()}catch(a){i("warning","proxy",`Break connections failed: ${a.message??String(a)}`)}}if(e==="open-providers"&&(s.activePage="providers"),e==="open-rules"&&(s.activePage="rules",await we()),e==="close-all"){let t=s.connections.length;s.closingAllConnections=!0,h();try{await p("close_all_connections"),i("warning","connection",`Closed ${t} active connections`),await X()}catch(a){s.controllerStatus="controller offline",i("warning","connection",`Controller close-all failed; keeping local rows: ${a.message??String(a)}`)}finally{s.closingAllConnections=!1}}if(e==="delay-test"){if(s.toggles.testingDelays){ve(),i("info","proxy","Delay test cancelled"),Y();return}let t=s.proxyGroups.find(o=>o.name===s.activeProxyGroup)??s.proxyGroups.find(o=>te(o.type)&&o.name.toUpperCase()!=="GLOBAL")??s.proxyGroups[0]??null,a=pt([...new Set((t?.options??[]).map(o=>o.name))].filter(o=>!["DIRECT","REJECT","REJECT-DROP","PASS","COMPATIBLE"].includes(String(o).toUpperCase())));if(!a.length)i("warning","proxy","No proxy nodes available for delay test");else if(N()?.core?.invoke){let o=w.delayTestGeneration=(w.delayTestGeneration??0)+1;s.toggles.testingDelays=!0,t&&t.options.forEach(r=>{a.includes(r.name)&&(r.delay=null,r.dead=!1)}),Y(a);try{let r=s.settingsSnapshot?.settings?.delayTestUrl??s.settingsSnapshot?.settings?.delay_test_url??null,n=new Map,l=0;for(;l<a.length&&o===w.delayTestGeneration;){let d=Be(),u=a.slice(l,l+d);l+=u.length;let g=await p("test_proxy_delays",{proxies:u,url:r,timeout_ms:5e3,timeoutMs:5e3,concurrency:d});if(o!==w.delayTestGeneration)break;let f=new Set;for(let m of g??[])f.add(m.name),Number.isFinite(m.delay)&&m.delay>0?(n.set(m.name,m.delay),fe(m.name,m.delay)):(n.set(m.name,0),fe(m.name,0));for(let m of u)!f.has(m)&&!n.has(m)&&(n.set(m,0),fe(m,0));Y(u)}if(o===w.delayTestGeneration){qe(a);let d=[...n.values()].filter(g=>g<=0).length+a.filter(g=>!n.has(g)).length,u=[...n.values()].filter(g=>g>0).length;i(d?"warning":"info","proxy",`Delay test (${t?.name??"group"}): ${u} ok${d?`, ${d} timed out`:""} \xB7 concurrency ${Be()}`)}}catch(r){(w.delayTestGeneration??0)===o&&(qe(a),i("warning","proxy",`Delay test failed: ${r.message??String(r)}`))}finally{(w.delayTestGeneration??0)===o&&(s.toggles.testingDelays=!1,Y(a))}}else s.proxyGroups.forEach(o=>{o.options.forEach((r,n)=>{r.delay>0&&(r.delay=Math.max(18,r.delay+(n%2===0?-5:7)))})}),i("info","proxy","Delay test completed in preview mode")}if(e==="reload-proxies"){let t=await X();i(t?"info":"warning","proxy",t?"Controller snapshot reloaded":"Controller unavailable; keeping local data")}if(e==="start-core")try{s.coreStatus=await p("start_core"),s.coreStatus?.state==="Running"&&(s.coreStartedAt=Date.now(),s.traffic.runtimeSeconds=0,H()),i("info","core",s.coreStatus.message),await X()}catch(t){s.coreStatus=await p("core_status"),i("error","core",t.message??String(t))}if(e==="install-pinned-core"||e==="install-latest-core")try{i("info","core","Installing pinned darwin-arm64 Mihomo core package...");let t=await p("install_pinned_mihomo_core");s.coreStatus=await p("core_status"),i("info","core",`Pinned core installed: ${S(t.bytes??0)} \xB7 ${String(t.sha256??"").slice(0,12)}`)}catch(t){i("error","core",`Core install failed: ${t.message??String(t)}`)}if(e==="install-pinned-clash-rs")try{i("info","core","Installing pinned clash-rs aarch64 (does not change default core)...");let t=await p("install_pinned_clash_rs_core");i("info","core",`Pinned clash-rs installed: ${S(t.bytes??0)} \xB7 ${String(t.sha256??"").slice(0,12)}`)}catch(t){i("error","core",`clash-rs install failed: ${t.message??String(t)}`)}if(e==="stop-core")try{s.coreStatus=await p("stop_core"),s.coreStartedAt=null,s.traffic.runtimeSeconds=0,H(),i("warning","core",s.coreStatus.message)}catch(t){i("error","core",t.message??String(t))}if(e==="copy-proxy-exports"){let t=s.settingsSnapshot?.settings?.mixed_port??7890,a=[`export https_proxy=http://127.0.0.1:${t}`,`export http_proxy=http://127.0.0.1:${t}`,`export all_proxy=socks5://127.0.0.1:${t}`].join(`
`);try{await navigator.clipboard.writeText(a),i("info","shell","Copied proxy export commands for Terminal")}catch(o){i("warning","clipboard",o.message??String(o))}}if(e==="toggle-random-mixed-port"){let t=!!(s.settingsSnapshot?.settings?.randomMixedPort??s.settingsSnapshot?.settings?.random_mixed_port);try{let a=await p("write_settings_snapshot",{settings:{...x(),randomMixedPort:!t,random_mixed_port:!t}});v(a),i("info","settings",`Random mixed-port ${t?"disabled":"enabled"}`)}catch(a){i("warning","settings",a.message??String(a))}}if(e==="allow-lan-info"){s.glassDialog={kind:"info",payload:{title:"Allow LAN",body:"Turn on to listen on all interfaces by default, or else only listen on 127.0.0.1. You can change the Bind Address on the right to specify a particular interface."}},_();return}if(e==="show-network-interfaces")try{let t=await p("network_diagnostics");s.networkDiagnostics=t,s.glassDialog={kind:"network-interfaces",payload:t?.services??[],defaultRoute:t?.default_route_interface??t?.defaultRouteInterface??"unknown"},_();return}catch(t){i("warning","network",t.message??String(t))}if(e==="edit-bind-address"){let t=s.settingsSnapshot?.settings??{};s.glassDialog={kind:"bind-address",payload:Ge(t)},_();return}if(e==="preview-runtime-config")try{let t=await p("read_runtime_config_text");s.glassDialog={kind:"preview-config",payload:t},_();return}catch(t){i("warning","core",`Config preview failed: ${t.message??String(t)}`)}if(e==="dns-query"){s.glassDialog={kind:"dns-query",payload:{name:"www.gstatic.com",type:"A",result:""}},_();return}if(e==="script-test"){s.glassDialog={kind:"script-test"},_();return}if(e==="open-controller-dashboard"){let t=s.settingsSnapshot?.settings??{},a=t.external_controller_host??"127.0.0.1",o=t.external_controller_port??9090,r=t.secret?encodeURIComponent(t.secret):"",n=`https://clash.razord.top/#/?host=${encodeURIComponent(a)}&port=${o}${r?`&secret=${r}`:""}`;try{await p("open_external_url",{url:n}),i("info","core",`Opened controller dashboard (${a}:${o})`)}catch(l){try{await navigator.clipboard.writeText(n),i("warning","core",`Open failed; URL copied instead: ${l.message??String(l)}`)}catch(d){i("info","core",n),i("warning","core",l.message??String(l)),i("warning","clipboard",d.message??String(d))}}return}if(e==="tun-info"){s.glassDialog={kind:"info",payload:{title:"TUN Mode",body:"To enable this mode, please install Service Mode first!"}},_();return}if(e==="tun-settings"){let t=s.settingsSnapshot?.settings??{};s.glassDialog={kind:"tun-settings",payload:{stack:t["tun-stack"]??t.tunStack??"mixed",autoRoute:t["tun-auto-route"]??t.tunAutoRoute??!0,strictRoute:t["tun-strict-route"]??t.tunStrictRoute??!0,dnsHijack:t["tun-dns-hijack"]??t.tunDnsHijack??`any:53
[::]:53`}},_();return}if(e==="tun-reset-dns"){let t=s.settingsSnapshot?.settings??{};s.glassDialog={kind:"tun-reset-dns",payload:t["restore-dns-servers"]??t.restoreDnsServers??"Empty"},_();return}if(e==="mixin-info"){s.glassDialog={kind:"info",payload:{title:"Mixin",body:"When Mixin is enabled, YAML is recursively merged into the generated config.yaml before the core reloads."}},_();return}if(e==="edit-mixin"){let t=s.settingsSnapshot?.settings??{};s.glassDialog={kind:"edit-mixin",payload:t.mixin_yaml??t.mixinYaml??s.mixinYaml??""},_();return}if(e==="open-home-directory")try{await p("reveal_home_directory"),i("info","shell","Home Directory opened in Finder")}catch(t){i("warning","shell",`Open Folder failed: ${t.message??String(t)}`)}if(e==="save-mixed-port"){let t=document.querySelector("[data-mixed-port]"),a=Number.parseInt(t?.value??"",10);if(!Number.isInteger(a)||a<1||a>65535)i("error","settings","mixed-port must be between 1 and 65535");else{let o=s.settingsSnapshot?.settings?.mixed_port??y.settings.mixed_port;try{let r=await p("write_settings_snapshot",{settings:{...x(),mixed_port:a}});if(v(r),P().active&&await p("apply_active_profile"),s.toggles.systemProxy){let n=await p("set_system_proxy_enabled",{enabled:!0});v(n)}i("info","settings",`mixed-port saved: ${a}${s.coreStatus?.state==="Running"?"; restart core to guarantee full reload":""}`)}catch(r){let n=await p("write_settings_snapshot",{settings:{...x(),mixed_port:o}});v(n),i("error","settings",`mixed-port refused: ${r.message??String(r)}`)}}}if(e==="import-profile"){let a=document.querySelector("[data-profile-url]")?.value?.trim();if(!a)i("warning","profile","Profile URL is required before download");else{let o=P().active?P().id:null,r=await p("import_profile_url",{url:a,name:null,activate:!0});await k();try{let n=await p("apply_active_profile");i("info","profile",`Remote profile imported and applied: ${r.name} (${S(n.bytes??r.bytes??0)})`)}catch(n){let l=await p("write_settings_snapshot",{settings:{...x(),active_profile:o}});v(l),await k(),i("error","profile",`Remote profile imported, but config apply failed: ${n.message??String(n)}`)}}}if(e==="paste-profile-url"){let t=document.querySelector("[data-profile-url]");try{let a=await navigator.clipboard.readText();t&&(t.value=a.trim()),i("info","profile","Profile URL pasted from clipboard")}catch{i("warning","profile","Clipboard read was refused")}}if(e==="import-profile-file"){let t=document.querySelector("[data-profile-file]"),a=t?.files?.[0];if(a){let o=P().active?P().id:null,r=await a.text(),n=await p("import_profile_text",{name:a.name,body:r,activate:!0});await k();try{let l=await p("apply_active_profile");i("info","profile",`Local profile imported and applied: ${n.name} (${S(l.bytes??n.bytes??0)})`)}catch(l){let d=await p("write_settings_snapshot",{settings:{...x(),active_profile:o}});v(d),await k(),i("error","profile",`Local profile imported, but config apply failed: ${l.message??String(l)}`)}finally{t&&(t.value="")}}else{t?.click();return}}if(e==="migrate-legacy-profiles"){let t=await p("migrate_legacy_cfw_profiles");if(await k(),P().active)try{let a=await p("apply_active_profile");i("info","profile",`Migrated ${t.length} CFW profile(s); active config applied (${S(a.bytes??0)})`)}catch(a){i("warning","profile",`Migrated ${t.length} CFW profile(s), but active config apply failed: ${a.message??String(a)}`)}else i("info","profile",`Migrated ${t.length} CFW profile(s)`)}if(e==="update-all-profiles"){let t=s.profiles.filter(r=>r.sourceUrl),a=0,o=0;for(let r of t)try{await p("update_profile",{id:r.id}),a+=1}catch(n){o+=1,i("warning","profile",`Update failed for ${r.name}: ${n.message??String(n)}`)}if(await k(),P().active)try{await p("apply_active_profile")}catch(r){i("warning","profile",`Active profile reapply failed: ${r.message??String(r)}`)}i(o?"warning":"info","profile",`Update All profiles completed: ${a} updated${o?`, ${o} failed`:""}`)}if(e==="save-profile-editor"){let t=document.querySelector("[data-profile-editor]"),a=s.profileInspector;if(!t||!a?.profile?.id)i("warning","profile","No profile editor is open");else{let o=await p("save_profile_text",{id:a.profile.id,body:t.value});o.active&&await p("apply_active_profile"),await k(),await B(o.id,"edit"),i("info","profile",`Profile YAML saved${o.active?" and active config hot-reloaded":""}: ${S(o.bytes??0)}`)}}if(e==="close-profile-inspector"&&(s.profileInspector=null),e==="update-all-providers"){s.providerBulkActions.add(e),h();try{let[t,a]=await Promise.allSettled([p("update_all_proxy_providers"),p("update_all_rule_providers")]),o=t.status==="fulfilled"?t.value:V("update-proxy"),r=a.status==="fulfilled"?a.value:V("update-rule");t.status==="rejected"&&i("warning","provider",`Proxy provider list failed: ${t.reason?.message??String(t.reason)}`),a.status==="rejected"&&i("warning","provider",`Rule provider list failed: ${a.reason?.message??String(a.reason)}`),await Q();let n=le("Proxy providers",o),l=le("Rule providers",r),d=ce(o)&&ce(r)&&t.status==="fulfilled"&&a.status==="fulfilled"?"info":"warning";i(d,"provider",`Update All completed \xB7 ${n} \xB7 ${l}`)}catch(t){s.controllerStatus="controller offline",i("warning","provider",`Update All failed: ${t.message??String(t)}`)}finally{s.providerBulkActions.delete(e),h()}}if(e==="health-check-all"){s.providerBulkActions.add(e),h();try{let t=await p("health_check_all_proxy_providers");await Q(),i(ce(t)?"info":"warning","provider",le("Health Check All",t))}catch(t){s.controllerStatus="controller offline",i("warning","provider",`Health Check All failed: ${t.message??String(t)}`)}finally{s.providerBulkActions.delete(e),h()}}if(e==="flush-fake-ip-cache")try{await p("flush_fake_ip_cache"),i("info","cache","Fake IP cache flushed through Clash controller")}catch(t){s.controllerStatus="controller offline",i("warning","cache",`Fake IP cache flush failed: ${t.message??String(t)}`)}if(e==="reload-rules"){let t=await we();i(t?"info":"warning","rules",t?`Loaded ${s.rules.length} controller rules`:"Rules controller endpoint unavailable")}if(e==="toggle-log-stream"&&(s.logsPaused=!s.logsPaused,i("info","logs",`Request logs ${s.logsPaused?"paused":"resumed"}`)),e==="clear-logs"&&(s.logs=[]),e==="copy-logs"){let t=s.logs.map(a=>{let o=a.time??a.at??"",r=a.level??"info",n=a.message??a.payload??String(a);return`[${o}] ${r} ${n}`}).join(`
`);try{await navigator.clipboard.writeText(t||"(no logs)"),i("info","logs",`Copied ${s.logs.length} log line(s) to clipboard`)}catch(a){i("warning","logs",`Copy logs refused: ${a.message??String(a)}`)}}if(e==="reveal-logs")try{await p("reveal_logs_directory"),i("info","logs","Logs folder opened in Finder")}catch(t){i("warning","logs",`Open Folder failed: ${t.message??String(t)}`)}if(e==="toggle-connection-stream"&&(s.connectionPaused=!s.connectionPaused,i("info","connections",`Connection view ${s.connectionPaused?"frozen":"unfrozen"}`)),e==="close-connection-detail"&&(s.connectionDetailId=null),e==="clear-connection-search"&&(s.connectionSearch=""),e==="clear-deep-links"&&(s.deepLinks=[]),e==="save-settings"){let t=await p("write_settings_snapshot",{settings:x()});if(v(t),s.toggles.systemProxy){let a=await p("set_system_proxy_enabled",{enabled:!0});v(a),await re()}if(P().active){let a=await p("apply_active_profile");i("info","settings",`cfw-settings.yaml saved; active config reapplied (${S(a.bytes??0)})`)}else i("info","settings","cfw-settings.yaml saved")}if(e==="check-for-updates")try{D({autoCheck:!0,checking:!0});let t=await p("check_for_updates");await Ve(t)}catch(t){i("warning","updater",`Update check failed: ${t.message??String(t)}`),D({autoCheck:!0,checking:!1,result:{available:!1,error:t.message??String(t),current:s.payload?.product?.version}})}if(e==="load-kernel-compare"||e==="show-kernel-compare"){let t=await je(e==="load-kernel-compare");if(!t?.comparison){i("warning","bench","No measured kernel compare report found");return}let a=t.comparison.narrative??{},o=t.comparison.headline??{};window.alert([`Measured clash-rs vs mihomo (${t.measured_at??"local"})`,"",a.speed??"",a.stability??"",a.weak_net??"","",`Headline: cold ${o.cold_start_speedup_x??"n/a"}\xD7 \xB7 API ${o.controller_api_speedup_x??"n/a"}\xD7 \xB7 weak-net ${o.weak_net_success_delta_pp??"n/a"} pp`,"Not a CFW 3\xD7 claim \u2014 same-machine core-vs-core only."].join(`
`)),h()}if(e==="reload-settings"&&(await ne(),i("info","settings","cfw-settings.yaml reloaded")),e==="manage-service-mode"){s.glassDialog={kind:"service-mode-manage"},_();return}if(e==="update-geoip-database"){if(s.geoipUpdating)return;s.glassDialog={kind:"geoip"},_();return}if(e==="install-helper-service")try{let t=await p("install_helper_service");v(t),i("info","helper","Privileged helper installed through launchd")}catch(t){i("warning","helper",`Helper install needs administrator context: ${t.message??String(t)}`)}if(e==="uninstall-helper-service")try{let t=await p("uninstall_helper_service");v(t),i("info","helper","Privileged helper removed from launchd")}catch(t){i("warning","helper",`Helper uninstall failed: ${t.message??String(t)}`)}if(e==="run-tray-script"){let t=await p("write_settings_snapshot",{settings:x()});v(t);try{let a=await p("run_tray_script"),o=[a.stdout,a.stderr].filter(Boolean).join(" \xB7 ");i(a.status===0?"info":"warning","action",`Tray Script exited ${a.status??"unknown"}${o?` \xB7 ${o}`:""}`)}catch(a){i("warning","action",`Tray Script failed: ${a.message??String(a)}`)}}if(e==="run-child-process"){let t=await p("write_settings_snapshot",{settings:x()});v(t);try{let a=await p("run_child_process"),o=[a.stdout,a.stderr].filter(Boolean).join(" \xB7 ");i(a.status===0?"info":"warning","action",`Child Process exited ${a.status??"unknown"}${o?` \xB7 ${o}`:""}`)}catch(a){i("warning","action",`Child Process failed: ${a.message??String(a)}`)}}if(e==="reset-settings"){s.glassDialog={kind:"reset-settings"},_();return}if(e==="quit-app"){await p("quit_app");return}if(e==="force-quit-app"){await p("force_quit_app");return}h()}async function he(e){if(e?.startsWith("proxy-select:")){let[,t,a]=e.split(":"),o=decodeURIComponent(t??""),r=decodeURIComponent(a??""),n=s.proxyGroups.find(l=>l.name===o);if(n&&r){let l=n.now;n.now=r;try{await p("select_proxy",{group:o,proxy:r}),i("info","tray",`Proxy group ${o} switched to ${r}`),s.toggles.breakOnProxyChange&&await oe(o)}catch(d){n.now=l,i("warning","tray",`Tray proxy selection failed: ${d.message??String(d)}`)}}}if(e?.startsWith("mode:")){let t=e.split(":")[1];if(["Global","Rule","Direct","Script"].includes(t)){let a=s.mode;s.mode=t;try{await p("set_proxy_mode",{mode:t});let o=await p("write_settings_snapshot",{settings:x()});v(o),i("info","tray",`Proxy mode switched to ${t}`),s.toggles.breakOnProxyChange&&await oe("tray mode")}catch(o){s.mode=a,i("warning","tray",`Mode switch failed: ${o.message??String(o)}`)}}}if(e==="toggle-system-proxy"&&await z("systemProxy",!s.toggles.systemProxy,"tray"),e==="toggle-tun-mode"&&await z("tunMode",!s.toggles.tunMode,"tray"),e==="toggle-mixin"&&await z("mixin",!s.toggles.mixin,"tray"),e==="close-all"){await O("close-all");return}if(e==="restart-core"){await O("stop-core"),await O("start-core");return}if(e==="run-tray-script")try{let t=await p("run_tray_script"),a=[t.stdout,t.stderr].filter(Boolean).join(" \xB7 ");i(t.status===0?"info":"warning","tray",`Tray Script exited ${t.status??"unknown"}${a?` \xB7 ${a}`:""}`)}catch(t){i("warning","tray",`Tray Script failed: ${t.message??String(t)}`)}if(e==="toggle-devtools")try{await p("toggle_devtools"),i("info","tray","DevTools toggled")}catch(t){i("warning","tray",t.message??String(t))}e==="move-dashboard"&&(await p("move_dashboard_to_nearest_monitor"),i("info","tray","Dashboard moved to the active monitor")),h()}function i(e,t,a){let o=new Date;s.logs.unshift({time:o.toTimeString().slice(0,8),level:de(e),source:t,message:a,fields:[]}),s.logs=s.logs.slice(0,ie)}function Wt(e){let t=(e??[]).map(a=>({time:a.time??"live",level:de(a.level),source:a.source??"core",message:a.message??"",fields:a.fields??[]}));s.logs=[...t.reverse(),...s.logs].slice(0,ie)}async function oe(e){let t=s.connections.length;if(t)try{await p("close_all_connections"),s.connections=[],s.connectionStream.rows=new Map,i("warning","connection",`Closed ${t} connection(s) after ${e} switch`)}catch(a){s.controllerStatus="controller offline",i("warning","connection",`Connection cleanup after ${e} switch failed: ${a.message??String(a)}`)}}async function B(e,t,a=null){let o=await p("read_profile_text",{id:e}),r={id:e,mode:t,profile:o,focusKey:a};if(t==="qrcode")try{r.svg=await p("profile_qrcode_svg",{id:e})}catch(n){r.error=n.message??String(n)}s.profileInspector=r}function Kt(e){if(!e)return;let t=document.querySelector("[data-profile-editor]");if(!(t instanceof HTMLTextAreaElement))return;let a=t.value,o=a.match(new RegExp(`^${e}\\s*:`,"im"));if(!o||o.index==null)return;let r=o.index;t.focus(),t.setSelectionRange(r,r+o[0].length);let l=a.slice(0,r).split(`
`).length-1,d=Number.parseFloat(getComputedStyle(t).lineHeight)||18;t.scrollTop=Math.max(0,l*d-40)}async function Yt(){s.payload=await p("boot_payload"),s.lastRefresh="Just now",await ne(),await tt(),await re(),await be(),await k(),h(),Promise.all([G(),Q()]).finally(()=>{i("info","shell","Boot payload reloaded from Rust"),h()})}async function ne(){let e=await p("read_settings_snapshot");v(e)}async function tt(){try{let e=await p("system_proxy_state");s.toggles.systemProxy=e==="Enabled",e==="External"&&i("info","sysproxy","macOS has a non-Clash proxy configured; Clash for Mac will not overwrite it unless you enable System Proxy here")}catch(e){i("warning","sysproxy",`Unable to read macOS system proxy: ${e.message??String(e)}`)}}async function ye(){try{s.tunRuntime=await p("tun_runtime_state"),s.toggles.tunMode=!!s.tunRuntime?.active}catch(e){s.tunRuntime=null,i("warning","tun",`Unable to read TUN runtime: ${e.message??String(e)}`)}}async function re(){try{s.networkDiagnostics=await p("network_diagnostics")}catch(e){s.networkDiagnostics=null,i("warning","network",`Unable to inspect macOS network services: ${e.message??String(e)}`)}}async function be(){let e=s.coreStatus?.state;try{s.coreStatus=await p("core_status")}catch(a){s.coreStatus=I,i("warning","core",a.message??String(a))}let t=s.coreStatus?.state;t==="Running"?((e!=="Running"||!s.coreStartedAt)&&(s.coreStartedAt=Date.now()),s.traffic.runtimeSeconds=Math.floor((Date.now()-s.coreStartedAt)/1e3)):(s.coreStartedAt=null,s.traffic.runtimeSeconds=0),H();try{s.serviceModeStatus=await p("service_mode_status")}catch{s.serviceModeStatus=null}try{s.geoipStatus=await p("geoip_database_status")}catch(a){s.geoipStatus=null,i("warning","geoip",`Unable to read GeoIP database: ${a.message??String(a)}`)}if(t==="Running")try{s.controllerVersion=await p("controller_version")}catch{s.controllerVersion=null}else s.controllerVersion=null}async function X(){try{let e=await p("controller_snapshot");return e?(st(e),p("refresh_tray_menu").catch(t=>{i("warning","tray",`Tray refresh failed: ${t.message??String(t)}`)}),i("info","controller","Live controller snapshot applied"),!0):(Ue(),s.controllerStatus="reference preview only",!1)}catch(e){return Ue(),s.controllerStatus="controller offline",i("warning","controller",e.message??String(e)),!1}}async function G(e=4,t=600){for(let a=0;a<e;a+=1){if(await X())return!0;a+1<e&&await Le(t)}return!1}function Ue(){N()?.core?.invoke&&(s.proxyGroups=[],s.connections=[],s.rules=[],s.connectionStream.rows=new Map)}async function Q(){try{let e=await p("providers_snapshot");return ot(e)?(i("info","provider","Live providers snapshot applied"),!0):!1}catch(e){return N()?.core?.invoke&&(s.providers=[],s.ruleProviders=[]),i("warning","provider",e.message??String(e)),!1}}async function we(){try{let e=await p("rules_snapshot"),t=Array.isArray(e?.rules)?e.rules:[];return s.rules=t.map(a=>({index:String(a.index??""),type:a.kind??a.type??"",payload:a.payload??"",proxy:a.proxy??"",provider:a.provider??"",hits:String(a.extra?.hitCount??a.extra?.hit_count??0),size:a.size??-1,extra:a.extra??{}})),i("info","rules",`Live rules snapshot applied: ${s.rules.length} rules`),!0}catch(e){return N()?.core?.invoke&&(s.rules=[]),i("warning","rules",e.message??String(e)),!1}}async function k(){try{let e=await p("profiles_snapshot");return Array.isArray(e)?(s.profiles=e.map(t=>({id:t.id,name:t.name,type:t.source_url?"Remote":"Local",updated:t.updated_epoch_secs?wt(t.updated_epoch_secs):"unknown",updatedEpochSecs:t.updated_epoch_secs??null,rules:t.rule_count??0,traffic:S(t.bytes??0),active:!!t.active,path:t.path,sourceUrl:t.source_url??null,subscriptionUserinfo:t.subscription_userinfo??null,updateInterval:t.update_interval??null,homeWeb:t.home_web??null})),!0):!1}catch(e){return s.profiles=[],i("warning","profile",e.message??String(e)),!1}}async function Xt(){try{await p("start_connections_stream")}catch(e){i("warning","connections",`Live stream unavailable: ${e.message??String(e)}`)}try{await p("start_log_stream")}catch(e){i("warning","logs",`Log stream unavailable: ${e.message??String(e)}`)}}async function Qt(e){let t=await p("parse_deep_links",{urls:e});for(let a of t??[]){if(a.error){i("warning","protocol",`${a.raw||"clash://"} parse failed: ${a.error}`);continue}let o=a.intent;if(o){if(o.action==="quit"){i("warning","protocol","clash://quit received"),await p("quit_app");continue}if((o.action==="install-config"||o.action==="install-profile")&&o.url)try{let r=P().active?P().id:null,n=await p("import_profile_url",{url:o.url,name:o.name,activate:!0});await k();try{let l=await p("apply_active_profile");i("info","protocol",`${o.action} imported and applied ${n.name} (${S(l.bytes??n.bytes??0)})`)}catch(l){let d=await p("write_settings_snapshot",{settings:{...x(),active_profile:r}});throw v(d),await k(),l}await ne()}catch(r){i("error","protocol",`${o.action} failed: ${r.message??String(r)}`)}else i("warning","protocol",`Unsupported clash:// intent ${o.action}`)}}}async function Jt(){Vt(),s.payload=await p("boot_payload"),await ne(),await tt(),await ye(),await re(),await be(),await k(),await je().catch(()=>null),h(),Promise.all([G(),Q()]).finally(h),document.getElementById("reload-button").addEventListener("click",Yt),await M("cfw://page",e=>{s.activePage=e.payload,h()}),await M("cfw://settings-changed",async e=>{e.payload&&v(e.payload),await ye(),await be(),await G(8,400).catch(()=>!1),h()}),await M("cfw://product-about",e=>{D({autoCheck:!!e.payload?.auto_check,checking:!!e.payload?.checking,result:s.updateInfo})}),await M("cfw://update-available",e=>{me(e.payload),s.glassDialog?.kind==="product-about"&&D({autoCheck:!0,checking:!1,result:e.payload}),(s.activePage==="general"||s.activePage==="settings"||s.activePage==="feedback")&&h()}),await M("cfw://menu-check-for-update",async e=>{try{if(e.payload?.error){i("warning","updater",`Update check failed: ${e.payload.error}`),me(e.payload),D({autoCheck:!0,checking:!1,result:e.payload}),h();return}await Ve(e.payload)}catch(t){i("warning","updater",`Update flow failed: ${t.message??String(t)}`)}}),await M("cfw://deep-link",e=>{s.deepLinks=Array.isArray(e.payload)?e.payload:[e.payload],s.deepLinks.length?(i("info","protocol",`Received ${s.deepLinks.length} clash:// URL(s)`),Qt(s.deepLinks).finally(h)):h()}),await M("cfw://tray-action",e=>{he(e.payload).catch(t=>{i("error","tray",t.message??String(t)),h()})}),await M("cfw://network-path",e=>{let t=e.payload?.interface??"unknown";ve(),s.proxyGroups.forEach(a=>{a.options.forEach(o=>{typeof o.delay=="number"&&(o.delay=null,o.dead=!1)})}),s.activePage==="proxies"&&Y(),i("info","network",`Default route changed (${t}); delay badges marked stale \u2014 re-run Delay Test`)}),await M("cfw://connections-snapshot",e=>{s.connectionPaused||(Ne(e.payload),H(),s.activePage==="connections"?It():s.activePage==="general"&&se())}),await M("cfw://core-status",e=>{s.coreStatus=e.payload,H(),s.activePage==="general"&&se()}),await M("cfw://log-lines",e=>{s.logsPaused||(Wt(e.payload),s.activePage==="logs"&&Ie())}),await M("cfw://stream-error",e=>{let t=e.payload??{},a=t.level??"warning";i(a,t.stream??"stream",t.message??"stream unavailable"),s.activePage==="logs"?Ie():s.activePage==="connections"&&se()}),await M("tauri://drag-drop",async e=>{let t=e.payload?.paths??[],a=t.filter(o=>/\.ya?ml$/i.test(o));if(!a.length){t.length&&i("warning","profile","Drag-drop ignored: only .yaml/.yml profile files are supported");return}for(let o of a)await Zt(o)}),await Xt(),window.setInterval(()=>{s.coreStatus?.state==="Running"?(s.coreStartedAt||(s.coreStartedAt=Date.now()),s.traffic.runtimeSeconds=Math.floor((Date.now()-s.coreStartedAt)/1e3)):(s.coreStartedAt=null,s.traffic.runtimeSeconds=0),H()},1e3)}async function Zt(e){let t=P().active?P().id:null;try{let a=await p("import_profile_file",{path:e,name:null,activate:!0});await k();try{let o=await p("apply_active_profile");i("info","profile",`Dropped profile imported and applied: ${a.name} (${S(o.bytes??a.bytes??0)})`)}catch(o){let r=await p("write_settings_snapshot",{settings:{...x(),active_profile:t}});v(r),await k(),i("error","profile",`Dropped profile imported, but config apply failed: ${o.message??String(o)}`)}se()}catch(a){i("error","profile",`Drag-drop import failed: ${a.message??String(a)}`)}}Jt().catch(e=>{document.body.innerHTML=`<pre class="fatal">${c(e.stack??e.message??String(e))}</pre>`});})();
