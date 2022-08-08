// Copyright (c) Microsoft Corporation. All rights reserved..
// Licensed under the MIT License.

use sample::Sample;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;

mod sample;

// Constants and Method headers were generated by bindgen
// (https://github.com/rust-lang/rust-bindgen)
pub const MMI_OK: u32 = 0;
pub type MmiHandle = *mut c_void;
pub type MmiJsonString = *mut c_char;

// MSFT change: Added the #[no_mangle] annotation, renamed
// parameters, and defined the methods
#[no_mangle]
pub extern "C" fn MmiGetInfo(
    client_name: *const c_char,
    payload: *mut MmiJsonString,
    payload_size_bytes: *mut c_int,
) -> c_int {
    unimplemented!("MmiGetInfo is not yet implemented");
}

#[no_mangle]
pub extern "C" fn MmiOpen(
    client_name: *const c_char,
    max_payload_size_bytes: c_uint,
) -> MmiHandle {
    if client_name.is_null() {
        println!("MmiOpen called with null clientName");
        return ptr::null_mut() as *mut c_void;
    }
    let sample_box: Box<Sample> = Box::<Sample>::new(Sample::new(max_payload_size_bytes));
    return Box::into_raw(sample_box) as *mut c_void;
}

#[no_mangle]
pub extern "C" fn MmiClose(client_session: MmiHandle) {
    // The "_" variable name is to throwaway anything stored into it 
    let _: Box<Sample> = unsafe { Box::from_raw(client_session as *mut Sample) };
}

#[no_mangle]
pub extern "C" fn MmiSet(
    client_session: MmiHandle,
    component_name: *const c_char,
    object_name: *const c_char,
    payload: MmiJsonString,
    payload_size_bytes: c_int,
) -> c_int {
    unimplemented!("MmiSet is not yet implemented");
}

#[no_mangle]
pub extern "C" fn MmiGet(
    client_session: MmiHandle,
    component_name: *const c_char,
    object_name: *const c_char,
    payload: *mut MmiJsonString,
    payload_size_bytes: *mut c_int,
) -> c_int {
    unimplemented!("MmiGet is not yet implemented");
}

#[no_mangle]
pub extern "C" fn MmiFree(payload: MmiJsonString) {
    unimplemented!("MmiFree is not yet implemented");
}
