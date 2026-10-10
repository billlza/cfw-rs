# Build 40053 System Proxy convergence correction

40053 was signed, notarized and installed. Its corrected Packet Tunnel service
name was accepted by macOS and reached the system extension approval step.
System Proxy activation still failed, including with the TUN request cancelled.
The application, frozen source and all original receipts remain unchanged.

A September 11 experiment compiled the production SystemProxyPreferences code
and exercised the existing CFW proxy endpoint through the equivalent localhost
and 127.0.0.1 names. SCPreferencesApplyChanges returned before the updated
SCDynamicStore values were visible. The immediate equality check rejected the
successful write after about 90 milliseconds; restoration hit the same stale
observation twice. The experiment restored the original network settings.

The successor waits up to two seconds for the effective proxy values to match,
after releasing the preferences lock. Missing or malformed observations fail
immediately. Persistently different values still fail, and ownership comparisons,
credential checks, signature checks and Authority transitions remain required.
Safe stage codes are recorded when a local start or cleanup fails.

The same live experiment passed with the correction, including restoration.
Four regression cases cover delayed activation, delayed restoration and immediate
rejection of unavailable or malformed state. The Swift suite passed 622 tests.
Build 40054 contains this product change and still requires installed application
validation; isolated preference tests are not full System Proxy or TUN acceptance.
