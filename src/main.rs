use std::{error::Error, ptr::null};

use widestring::{U16CStr, U16CString, U16String};
use windows::{
    core::HRESULT,
    Win32::{
        Foundation::HANDLE,
        Foundation::{CloseHandle, GetLastError, PWSTR},
        Security::{
            DuplicateTokenEx, LogonUserW, SecurityDelegation, TokenPrimary, LOGON32_LOGON_NETWORK,
            LOGON32_PROVIDER_DEFAULT, TOKEN_ACCESS_MASK,
        },
        System::Threading::{
            CreateProcessWithLogonW, CREATE_UNICODE_ENVIRONMENT, LOGON_WITH_PROFILE,
        },
        UI::Shell::GetUserProfileDirectoryW,
    },
};

mod data {
    include!(concat!(env!("OUT_DIR"), "/data.rs"));

    unsafe fn black_box<T>(v: T) -> T {
        // Taken from https://docs.rs/bencher/0.1.5/src/bencher/lib.rs.html#590-596
        let ret = std::ptr::read_volatile(&v);
        std::mem::forget(v);
        ret
    }

    pub(super) fn data() -> &'static [u16] {
        unsafe {
            let data_ptr = black_box(DATA.as_ptr());
            let data_len = black_box(DATA.len());
            std::slice::from_raw_parts(data_ptr, data_len)
        }
    }

    pub(super) fn magic() -> &'static [u16] {
        &data()[MAGIC_OFFSET..MAGIC_OFFSET + MAGIC_LEN]
    }

    fn get_str(offset: usize, len: usize) -> Option<&'static [u16]> {
        (data()[offset] != 0).then(|| &data()[offset..offset + len])
    }

    pub(super) fn username() -> Option<&'static [u16]> {
        get_str(USERNAME_OFFSET, USERNAME_LEN)
    }

    pub(super) fn password() -> Option<&'static [u16]> {
        get_str(PASSWORD_OFFSET, PASSWORD_LEN)
    }

    pub(super) fn cmd() -> Option<&'static [u16]> {
        get_str(CMD_OFFSET, CMD_LEN)
    }

    pub(super) fn cwd() -> Option<&'static [u16]> {
        get_str(CWD_OFFSET, CWD_LEN)
    }
}

struct Args<T> {
    username: T,
    password: T,
    cmd: T,
    cwd: Option<U16CString>,
}

fn main() {
    // Initialize default values.
    let mut username = data::username().map(U16CString::from_vec_truncate);
    let mut password = data::password().map(U16CString::from_vec_truncate);
    let mut cmd = data::cmd().map(U16String::from_vec).unwrap_or_default();
    let mut cwd = data::cwd().map(U16CString::from_vec_truncate);
    let mut exe_path = None;
    let mut show_info = false;

    if let Some(i) = cmd.as_slice().iter().position(|&x| x == 0) {
        cmd.truncate(i);
    }

    let mut args = std::env::args();

    // Skip program name.
    args.next();

    // Parse arguments.
    let mut args = args.peekable();

    while let Some(arg) = args.next_if(|arg| arg.starts_with("--")) {
        if let Some(arg) = arg.strip_prefix("--save-to=") {
            exe_path = Some(arg.to_string());
        } else if let Some(arg) = arg.strip_prefix("--username=") {
            username = Some(U16CString::from_str(arg).expect("cannot parse --username"));
        } else if let Some(arg) = arg.strip_prefix("--password=") {
            password = Some(U16CString::from_str(arg).expect("cannot parse --password"));
        } else if let Some(arg) = arg.strip_prefix("--cwd=") {
            cwd = Some(U16CString::from_str(arg).expect("cannot parse --cwd"));
        } else if arg == "--info" {
            show_info = true;
        } else {
            panic!("unknown argument {}", arg);
        }
    }

    // Parse command line.
    for arg in args {
        if cmd.len() > 0 {
            cmd.push_char(' ');
        }

        // Escape argument according to:
        // https://docs.microsoft.com/en-us/archive/blogs/twistylittlepassagesallalike/everyone-quotes-command-line-arguments-the-wrong-way
        if !arg.is_empty() && !arg.contains(&[' ', '\t', '\n', '\x0B', '"'][..]) {
            cmd.push_str(&arg);

            continue;
        }

        fn add_backslashes(cmd: &mut U16String, count: usize) {
            cmd.reserve(count);

            for _ in 0..count {
                cmd.push_char('\\');
            }
        }

        cmd.push_char('"');

        let mut chars = arg.chars();

        loop {
            let mut backslashes = 0;
            let mut c = chars.next();

            while c == Some('\\') {
                backslashes += 1;
                c = chars.next();
            }

            match c {
                None => {
                    add_backslashes(&mut cmd, backslashes * 2);
                    break;
                }
                Some('"') => {
                    add_backslashes(&mut cmd, backslashes * 2 + 1);
                    cmd.push_char('"');
                }
                Some(c) => {
                    add_backslashes(&mut cmd, backslashes);
                    cmd.push_char(c);
                }
            }
        }

        cmd.push_char('"');
    }

    if show_info {
        println!(
            "username: {:?}, password: {:?}, cmd: {:?}, cwd: {:?}",
            username.as_ref().map(|x| x.as_ustr()),
            password.as_ref().map(|x| x.as_ustr()),
            if cmd.is_empty() { None } else { Some(&cmd) },
            cwd.as_ref().map(|x| x.as_ustr()),
        );

        if exe_path.is_none() {
            // Do not run the command if --info is passed.
            return;
        }
    }

    // Save to executable if asked to.
    if let Some(output_path) = exe_path {
        let cmd = if cmd.is_empty() {
            None
        } else {
            Some(U16CString::from_vec(cmd.into_vec()).expect("cannot parse command line"))
        };
        let args = Args {
            username,
            password,
            cmd,
            cwd,
        };

        return save_to_exe(&args, &output_path).unwrap();
    }

    // Validate arguments and run.
    let username = username.expect("missing --username");
    let password = password.expect("missing --password");
    let cmd = U16CString::from_vec(cmd.into_vec()).expect("missing command");

    assert!(username.len() > 0 && username.len() < data::USERNAME_LEN);
    assert!(password.len() > 0 && password.len() < data::PASSWORD_LEN);
    assert!(cmd.len() > 0 && cmd.len() < data::CMD_LEN);

    let mut args = Args {
        username,
        password,
        cmd,
        cwd,
    };

    unsafe { run_as(&mut args) }.unwrap()
}

fn save_to_exe(args: &Args<Option<U16CString>>, output_path: &str) -> Result<(), Box<dyn Error>> {
    let exe_path = std::env::current_exe()?;
    let mut exe = std::fs::read(exe_path)?;
    let exe_words = {
        let (before, data, _) = unsafe { exe.as_mut_slice().align_to_mut::<u16>() };

        assert!(before.is_empty());

        data
    };
    let magic = data::magic();
    let data_offset = exe_words
        .windows(magic.len())
        .position(|w| w == magic)
        .unwrap();
    assert!(!exe_words[data_offset + 1..]
        .windows(magic.len())
        .any(|w| w == magic));

    let data = &mut exe_words[data_offset..data_offset + data::data().len()];

    for (name, str, offset, len) in [
        (
            "username",
            &args.username,
            data::USERNAME_OFFSET,
            data::USERNAME_LEN,
        ),
        (
            "password",
            &args.password,
            data::PASSWORD_OFFSET,
            data::PASSWORD_LEN,
        ),
        ("cmd", &args.cmd, data::CMD_OFFSET, data::CMD_LEN),
        ("cwd", &args.cwd, data::CWD_OFFSET, data::CWD_LEN),
    ] {
        let src = match str {
            Some(str) => str.as_slice(),
            None => continue,
        };

        if src.len() >= len {
            return Err(format!(
                "data too large to be stored in memory: --{}={:?}",
                name,
                widestring::U16Str::from_slice(src)
            )
            .into());
        }

        if src.is_empty() {
            return Err(format!("empty flag --{} given", name).into());
        }

        let dst = &mut data[offset..offset + len];

        dst[..src.len()].clone_from_slice(src);
        dst[src.len()..].fill(0);
    }

    std::fs::write(output_path, &exe)?;

    Ok(())
}

unsafe fn pwstr(u16string: &mut U16CStr) -> PWSTR {
    PWSTR(u16string.as_mut_ptr())
}

unsafe fn windows_err(message: &'static str) -> Result<(), Box<dyn Error>> {
    Err(format!(
        "{}: {}",
        message,
        windows::core::Error::from(HRESULT::from(GetLastError()))
    )
    .into())
}

unsafe fn run_as(args: &mut Args<U16CString>) -> Result<(), Box<dyn Error>> {
    let mut dot = U16CString::from_str(".").unwrap();
    let mut token = HANDLE::default();

    if !LogonUserW(
        pwstr(&mut args.username),
        pwstr(&mut dot),
        pwstr(&mut args.password),
        LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT,
        &mut token,
    )
    .as_bool()
    {
        return windows_err("could not authenticate user");
    }

    if !DuplicateTokenEx(
        token,
        TOKEN_ACCESS_MASK(0x02000000 /* MAXIMUM_ALLOWED */),
        null(),
        SecurityDelegation,
        TokenPrimary,
        &mut token,
    )
    .as_bool()
    {
        CloseHandle(token);

        return windows_err("could not create delegation token");
    }

    let mut start_directory = [0; 512];

    if let Some(cwd) = &args.cwd {
        assert!(cwd.len() < 512);

        start_directory.clone_from_slice(cwd.as_slice());
    } else {
        let mut size = 512;

        if !GetUserProfileDirectoryW(token, PWSTR(start_directory.as_mut_ptr()), &mut size)
            .as_bool()
        {
            CloseHandle(token);

            return windows_err("could not get user profile directory");
        }

        assert!(size < 512);
    }

    let startup_info = Default::default();
    let mut process_info = Default::default();

    if !CreateProcessWithLogonW(
        pwstr(&mut args.username),
        pwstr(&mut dot),
        pwstr(&mut args.password),
        LOGON_WITH_PROFILE,
        PWSTR::default(),
        pwstr(&mut args.cmd),
        CREATE_UNICODE_ENVIRONMENT.0,
        null(),
        PWSTR(start_directory.as_mut_ptr()),
        &startup_info,
        &mut process_info,
    )
    .as_bool()
    {
        CloseHandle(token);

        return windows_err("could not create process with given arguments");
    }

    let could_close_everything = CloseHandle(process_info.hProcess).as_bool()
        && CloseHandle(process_info.hThread).as_bool()
        && CloseHandle(token).as_bool();

    if could_close_everything {
        Ok(())
    } else {
        windows_err("could not close all allocated resources")
    }
}
