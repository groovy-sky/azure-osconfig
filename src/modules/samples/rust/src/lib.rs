// Copyright (c) Microsoft Corporation. All rights reserved..
// Licensed under the MIT License.

use libc::EINVAL;
use libc::ENOMEM;
use libc::{c_char, c_int, c_uint, c_void};
use sample::Sample;
use sample::INFO;
use std::ffi::CStr;
use std::ffi::CString;
use std::ptr;

mod sample;

// Constants and Method headers were generated by bindgen
// (https://github.com/rust-lang/rust-bindgen)
pub const MMI_OK: i32 = 0;
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
    if client_name.is_null() {
        println!("MmiGetInfo called with null clientName");
        EINVAL
    } else if payload.is_null() {
        println!("MmiGetInfo called with null payload");
        EINVAL
    } else if payload_size_bytes.is_null() {
        println!("MmiGetInfo called with null payloadSizeBytes");
        EINVAL
    } else {
        // Take ownership of the client_name ptr
        let client_name_cstr: &CStr = unsafe { CStr::from_ptr(client_name) };
        let client_name_str_slice: &str;
        match client_name_cstr.to_str() {
            Ok(s) => client_name_str_slice = s,
            Err(e) => {
                println!("MmiGetInfo failed to read the clientName");
                return libc::EINVAL;
            }
        }
        let payload_string: CString;
        match CString::new(Sample::get_info(client_name_str_slice)) {
            Ok(s) => payload_string = s,
            Err(e) => {
                println!("MmiGetInfo failed to allocate memory");
                return libc::ENOMEM;
            }
        }
        let payload_ptr: MmiJsonString = CString::into_raw(payload_string);
        unsafe {
            *payload = payload_ptr;
            *payload_size_bytes = INFO.len() as i32;
        }
        MMI_OK
    }
}

#[no_mangle]
pub extern "C" fn MmiOpen(client_name: *const c_char, max_payload_size_bytes: c_uint) -> MmiHandle {
    if client_name.is_null() {
        println!("MmiOpen called with null clientName");
        ptr::null_mut() as *mut c_void
    } else {
        let sample_box: Box<Sample> = Box::<Sample>::new(Sample::new(max_payload_size_bytes));
        Box::into_raw(sample_box) as *mut c_void
    }
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
