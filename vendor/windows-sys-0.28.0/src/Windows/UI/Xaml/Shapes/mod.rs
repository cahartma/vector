#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, clashing_extern_declarations, clippy::all)]
#[link(name = "windows")]
extern "system" {}
pub type Ellipse = *mut ::core::ffi::c_void;
pub type Line = *mut ::core::ffi::c_void;
pub type Path = *mut ::core::ffi::c_void;
pub type Polygon = *mut ::core::ffi::c_void;
pub type Polyline = *mut ::core::ffi::c_void;
pub type Rectangle = *mut ::core::ffi::c_void;
pub type Shape = *mut ::core::ffi::c_void;
