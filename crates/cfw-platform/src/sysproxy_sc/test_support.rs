//! An in-memory stand-in for SystemConfiguration. The cutover and the
//! diagnostics run on it in tests, so no test reads or changes this Mac's
//! network settings.
//!
//! A store holds the committed services. Each session works on its own copy
//! and commits its staged configurations back, as SCPreferences sessions do.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use anyhow::{Result, bail};
use objc2_core_foundation::{CFDictionary, CFNumber, CFRetained, CFString, CFType};
use objc2_system_configuration::{
    kSCPropNetProxiesExcludeSimpleHostnames, kSCPropNetProxiesHTTPEnable,
    kSCPropNetProxiesHTTPPort, kSCPropNetProxiesHTTPProxy, kSCPropNetProxiesHTTPSEnable,
    kSCPropNetProxiesHTTPSPort, kSCPropNetProxiesHTTPSProxy,
    kSCPropNetProxiesProxyAutoConfigEnable, kSCPropNetProxiesProxyAutoDiscoveryEnable,
    kSCPropNetProxiesSOCKSEnable, kSCPropNetProxiesSOCKSPort, kSCPropNetProxiesSOCKSProxy,
};

use crate::sysproxy_sc::store::{ProxyConfiguration, ProxyPreferences, ProxyService};
use crate::sysproxy_sc::values::as_config_dict;

/// A service's Proxies protocol as the store holds it.
#[derive(Clone)]
pub(crate) enum FakeProxies {
    NoProtocol,
    Unconfigured,
    Configured(CFRetained<CFDictionary>),
}

#[derive(Clone)]
pub(crate) struct FakeService {
    pub(crate) identifier: Option<String>,
    pub(crate) display_name: Option<String>,
    pub(crate) proxies: FakeProxies,
    /// SystemConfiguration refuses to stage a configuration for this service.
    pub(crate) refuses_staging: bool,
}

impl FakeService {
    pub(crate) fn new(identifier: &str, display_name: &str, proxies: FakeProxies) -> Self {
        Self {
            identifier: Some(identifier.to_owned()),
            display_name: Some(display_name.to_owned()),
            proxies,
            refuses_staging: false,
        }
    }

    pub(crate) fn configured(identifier: &str, display_name: &str, proxies: Proxies) -> Self {
        Self::new(
            identifier,
            display_name,
            FakeProxies::Configured(proxies.build()),
        )
    }

    /// The committed configuration rendered as text, keyed by setting name.
    pub(crate) fn settings(&self) -> BTreeMap<String, String> {
        match &self.proxies {
            FakeProxies::Configured(dictionary) => render(dictionary),
            FakeProxies::NoProtocol | FakeProxies::Unconfigured => {
                panic!("the service has no proxy configuration")
            }
        }
    }
}

/// A session step the store can be told to fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Open,
    Lock,
    List,
    Commit,
}

/// What a session did to the store, in order. A step told to fail is
/// recorded before it fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    Opened,
    Locked,
    Listed,
    Staged(String),
    Committed,
}

#[derive(Default)]
pub(crate) struct FakeStore {
    services: RefCell<Vec<FakeService>>,
    failing: RefCell<Vec<Step>>,
    events: RefCell<Vec<Event>>,
}

impl FakeStore {
    pub(crate) fn with_services(services: Vec<FakeService>) -> Self {
        Self {
            services: RefCell::new(services),
            ..Self::default()
        }
    }

    /// Makes every later `step` fail.
    pub(crate) fn fail(&self, step: Step) {
        self.failing.borrow_mut().push(step);
    }

    pub(crate) fn events(&self) -> Vec<Event> {
        self.events.borrow().clone()
    }

    /// The committed state of the service at `index`.
    pub(crate) fn service(&self, index: usize) -> FakeService {
        self.services.borrow()[index].clone()
    }

    /// Changes a committed service, as another process would.
    pub(crate) fn replace(&self, index: usize, service: FakeService) {
        self.services.borrow_mut()[index] = service;
    }

    pub(crate) fn open(&self) -> Result<FakeSession<'_>> {
        self.step(Step::Open, Event::Opened)?;
        Ok(FakeSession {
            store: self,
            working: Rc::new(RefCell::new(self.services.borrow().clone())),
        })
    }

    fn step(&self, step: Step, event: Event) -> Result<()> {
        self.events.borrow_mut().push(event);
        if self.failing.borrow().contains(&step) {
            bail!("fake SystemConfiguration refused {step:?}")
        }
        Ok(())
    }
}

pub(crate) struct FakeSession<'a> {
    store: &'a FakeStore,
    working: Rc<RefCell<Vec<FakeService>>>,
}

impl<'a> ProxyPreferences for FakeSession<'a> {
    type Service = FakeSessionService<'a>;

    fn lock(&mut self) -> Result<()> {
        self.store.step(Step::Lock, Event::Locked)
    }

    fn services(&self) -> Result<Vec<Self::Service>> {
        self.store.step(Step::List, Event::Listed)?;
        Ok((0..self.working.borrow().len())
            .map(|index| FakeSessionService {
                store: self.store,
                working: Rc::clone(&self.working),
                index,
            })
            .collect())
    }

    fn commit_apply(&self) -> Result<()> {
        self.store.step(Step::Commit, Event::Committed)?;
        *self.store.services.borrow_mut() = self.working.borrow().clone();
        Ok(())
    }
}

pub(crate) struct FakeSessionService<'a> {
    store: &'a FakeStore,
    working: Rc<RefCell<Vec<FakeService>>>,
    index: usize,
}

impl ProxyService for FakeSessionService<'_> {
    fn identifier(&self) -> Option<String> {
        self.working.borrow()[self.index].identifier.clone()
    }

    fn display_name(&self) -> Option<String> {
        self.working.borrow()[self.index].display_name.clone()
    }

    fn proxy_configuration(&self) -> ProxyConfiguration {
        match &self.working.borrow()[self.index].proxies {
            FakeProxies::NoProtocol => ProxyConfiguration::NoProtocol,
            FakeProxies::Unconfigured => ProxyConfiguration::Unconfigured,
            FakeProxies::Configured(dictionary) => {
                ProxyConfiguration::Configured(dictionary.clone())
            }
        }
    }

    fn stage_proxy_configuration(&self, configuration: &CFDictionary) -> bool {
        let mut working = self.working.borrow_mut();
        let service = &mut working[self.index];
        if service.refuses_staging {
            return false;
        }
        // SystemConfiguration keeps its own copy of a staged dictionary.
        let copy = CFDictionary::new_copy(None, Some(configuration))
            .expect("copy the staged configuration");
        service.proxies = FakeProxies::Configured(copy);
        let identifier = service.identifier.clone().unwrap_or_default();
        drop(working);
        self.store
            .events
            .borrow_mut()
            .push(Event::Staged(identifier));
        true
    }
}

/// One of the three proxy protocols a service configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    Web,
    SecureWeb,
    Socks,
}

impl Protocol {
    pub(crate) const ALL: [Self; 3] = [Self::Web, Self::SecureWeb, Self::Socks];

    /// The enable, server and port keys of the protocol.
    pub(crate) fn keys(self) -> [&'static CFString; 3] {
        // SAFETY: the SystemConfiguration key constants are immutable CFStrings.
        unsafe {
            match self {
                Self::Web => [
                    kSCPropNetProxiesHTTPEnable,
                    kSCPropNetProxiesHTTPProxy,
                    kSCPropNetProxiesHTTPPort,
                ],
                Self::SecureWeb => [
                    kSCPropNetProxiesHTTPSEnable,
                    kSCPropNetProxiesHTTPSProxy,
                    kSCPropNetProxiesHTTPSPort,
                ],
                Self::Socks => [
                    kSCPropNetProxiesSOCKSEnable,
                    kSCPropNetProxiesSOCKSProxy,
                    kSCPropNetProxiesSOCKSPort,
                ],
            }
        }
    }
}

pub(crate) fn pac_enable_key() -> &'static CFString {
    // SAFETY: an immutable SystemConfiguration key constant.
    unsafe { kSCPropNetProxiesProxyAutoConfigEnable }
}

pub(crate) fn wpad_enable_key() -> &'static CFString {
    // SAFETY: an immutable SystemConfiguration key constant.
    unsafe { kSCPropNetProxiesProxyAutoDiscoveryEnable }
}

/// A setting the cutover never touches.
pub(crate) fn exclude_simple_hostnames_key() -> &'static CFString {
    // SAFETY: an immutable SystemConfiguration key constant.
    unsafe { kSCPropNetProxiesExcludeSimpleHostnames }
}

pub(crate) fn number(value: i32) -> CFRetained<CFType> {
    CFNumber::new_i32(value).into()
}

pub(crate) fn float(value: f64) -> CFRetained<CFType> {
    CFNumber::new_f64(value).into()
}

pub(crate) fn text(value: &str) -> CFRetained<CFType> {
    CFString::from_str(value).into()
}

/// A proxy configuration dictionary under construction.
#[derive(Default)]
pub(crate) struct Proxies {
    entries: Vec<(&'static CFString, CFRetained<CFType>)>,
}

impl Proxies {
    /// Every protocol on `server:port`, PAC and WPAD off, and one unrelated
    /// setting: the retired installation's own configuration when the server is
    /// `127.0.0.1` and the port its endpoint.
    pub(crate) fn every_protocol(server: &str, port: i32) -> Self {
        Protocol::ALL
            .into_iter()
            .fold(Self::default(), |proxies, protocol| {
                proxies.protocol(protocol, 1, server, port)
            })
            .with(pac_enable_key(), number(0))
            .with(wpad_enable_key(), number(0))
            .with(exclude_simple_hostnames_key(), number(1))
    }

    /// Every protocol off without a server or port, as the cutover leaves it.
    pub(crate) fn cleared() -> Self {
        Protocol::ALL
            .into_iter()
            .fold(Self::default(), |proxies, protocol| {
                proxies.with(protocol.keys()[0], number(0))
            })
            .with(exclude_simple_hostnames_key(), number(1))
    }

    pub(crate) fn protocol(
        self,
        protocol: Protocol,
        enabled: i32,
        server: &str,
        port: i32,
    ) -> Self {
        let [enable, host, port_key] = protocol.keys();
        self.with(enable, number(enabled))
            .with(host, text(server))
            .with(port_key, number(port))
    }

    /// Sets `key`, replacing an earlier value.
    pub(crate) fn with(mut self, key: &'static CFString, value: CFRetained<CFType>) -> Self {
        self.entries.retain(|(existing, _)| *existing != key);
        self.entries.push((key, value));
        self
    }

    pub(crate) fn build(self) -> CFRetained<CFDictionary> {
        let keys = self.entries.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        let values = self
            .entries
            .iter()
            .map(|(_, value)| &**value)
            .collect::<Vec<_>>();
        let typed = CFDictionary::<CFString, CFType>::from_slices(&keys, &values);
        CFRetained::from(&*typed)
    }
}

/// Every entry of a configuration rendered as text: numbers in decimal,
/// strings as they are.
pub(crate) fn render(dictionary: &CFDictionary) -> BTreeMap<String, String> {
    let (keys, values) = as_config_dict(dictionary).to_vecs();
    keys.into_iter()
        .zip(values)
        .map(|(key, value)| {
            let value = match value.downcast::<CFNumber>() {
                Ok(number) => number.as_i64().expect("integer").to_string(),
                Err(value) => value
                    .downcast::<CFString>()
                    .map(|text| text.to_string())
                    .expect("number or string"),
            };
            (key.to_string(), value)
        })
        .collect()
}
