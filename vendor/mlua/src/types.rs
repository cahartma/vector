use std::hash::{Hash, Hasher};
use std::os::raw::{c_int, c_void};
use std::sync::{Arc, Mutex};
use std::{fmt, mem, ptr};

#[cfg(feature = "lua54")]
use std::ffi::CStr;

#[cfg(feature = "async")]
use futures_core::future::LocalBoxFuture;

use crate::error::Result;
use crate::ffi;
use crate::hook::Debug;
use crate::lua::Lua;
use crate::util::{assert_stack, StackGuard};
use crate::value::MultiValue;

/// Type of Lua integer numbers.
pub type Integer = ffi::lua_Integer;
/// Type of Lua floating point numbers.
pub type Number = ffi::lua_Number;

/// A "light" userdata value. Equivalent to an unmanaged raw pointer.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct LightUserData(pub *mut c_void);

pub(crate) type Callback<'lua, 'a> =
    Box<dyn Fn(&'lua Lua, MultiValue<'lua>) -> Result<MultiValue<'lua>> + 'a>;

pub(crate) struct CallbackUpvalue<'lua> {
    pub(crate) lua: Lua,
    pub(crate) func: Callback<'lua, 'static>,
}

#[cfg(feature = "async")]
pub(crate) type AsyncCallback<'lua, 'a> =
    Box<dyn Fn(&'lua Lua, MultiValue<'lua>) -> LocalBoxFuture<'lua, Result<MultiValue<'lua>>> + 'a>;

#[cfg(feature = "async")]
pub(crate) struct AsyncCallbackUpvalue<'lua> {
    pub(crate) lua: Lua,
    pub(crate) func: AsyncCallback<'lua, 'static>,
}

#[cfg(feature = "async")]
pub(crate) struct AsyncPollUpvalue<'lua> {
    pub(crate) lua: Lua,
    pub(crate) fut: LocalBoxFuture<'lua, Result<MultiValue<'lua>>>,
}

#[cfg(feature = "send")]
pub(crate) type HookCallback = Arc<Mutex<dyn FnMut(&Lua, Debug) -> Result<()> + Send>>;

#[cfg(not(feature = "send"))]
pub(crate) type HookCallback = Arc<Mutex<dyn FnMut(&Lua, Debug) -> Result<()>>>;

#[cfg(all(feature = "send", feature = "lua54"))]
pub(crate) type WarnCallback = Box<dyn Fn(&Lua, &CStr, bool) -> Result<()> + Send>;

#[cfg(all(not(feature = "send"), feature = "lua54"))]
pub(crate) type WarnCallback = Box<dyn Fn(&Lua, &CStr, bool) -> Result<()>>;

#[cfg(feature = "send")]
pub trait MaybeSend: Send {}
#[cfg(feature = "send")]
impl<T: Send> MaybeSend for T {}

#[cfg(not(feature = "send"))]
pub trait MaybeSend {}
#[cfg(not(feature = "send"))]
impl<T> MaybeSend for T {}

pub(crate) struct DestructedUserdataMT;

/// An auto generated key into the Lua registry.
///
/// This is a handle to a value stored inside the Lua registry. It is not automatically
/// garbage collected on Drop, but it can be removed with [`Lua::remove_registry_value`],
/// and instances not manually removed can be garbage collected with [`Lua::expire_registry_values`].
///
/// Be warned, If you place this into Lua via a [`UserData`] type or a rust callback, it is *very
/// easy* to accidentally cause reference cycles that the Lua garbage collector cannot resolve.
/// Instead of placing a [`RegistryKey`] into a [`UserData`] type, prefer instead to use
/// [`AnyUserData::set_user_value`] / [`AnyUserData::get_user_value`].
///
/// [`UserData`]: crate::UserData
/// [`RegistryKey`]: crate::RegistryKey
/// [`Lua::remove_registry_value`]: crate::Lua::remove_registry_value
/// [`Lua::expire_registry_values`]: crate::Lua::expire_registry_values
/// [`AnyUserData::set_user_value`]: crate::AnyUserData::set_user_value
/// [`AnyUserData::get_user_value`]: crate::AnyUserData::get_user_value
pub struct RegistryKey {
    pub(crate) registry_id: c_int,
    pub(crate) unref_list: Arc<Mutex<Option<Vec<c_int>>>>,
}

impl fmt::Debug for RegistryKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RegistryKey({})", self.registry_id)
    }
}

impl Hash for RegistryKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.registry_id.hash(state)
    }
}

impl PartialEq for RegistryKey {
    fn eq(&self, other: &RegistryKey) -> bool {
        self.registry_id == other.registry_id && Arc::ptr_eq(&self.unref_list, &other.unref_list)
    }
}

impl Eq for RegistryKey {}

impl Drop for RegistryKey {
    fn drop(&mut self) {
        let mut unref_list = mlua_expect!(self.unref_list.lock(), "unref list poisoned");
        if let Some(list) = unref_list.as_mut() {
            list.push(self.registry_id);
        }
    }
}

impl RegistryKey {
    // Destroys the RegistryKey without adding to the drop list
    pub(crate) fn take(self) -> c_int {
        let registry_id = self.registry_id;
        unsafe {
            ptr::read(&self.unref_list);
            mem::forget(self);
        }
        registry_id
    }
}

pub(crate) struct LuaRef<'lua> {
    pub(crate) lua: &'lua Lua,
    pub(crate) index: c_int,
}

impl<'lua> fmt::Debug for LuaRef<'lua> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ref({})", self.index)
    }
}

impl<'lua> Clone for LuaRef<'lua> {
    fn clone(&self) -> Self {
        self.lua.clone_ref(self)
    }
}

impl<'lua> Drop for LuaRef<'lua> {
    fn drop(&mut self) {
        if self.index > 0 {
            self.lua.drop_ref(self);
        }
    }
}

impl<'lua> PartialEq for LuaRef<'lua> {
    fn eq(&self, other: &Self) -> bool {
        let lua = self.lua;
        unsafe {
            let _sg = StackGuard::new(lua.state);
            assert_stack(lua.state, 2);
            lua.push_ref(self);
            lua.push_ref(other);
            ffi::lua_rawequal(lua.state, -1, -2) == 1
        }
    }
}
