use std::env;
use std::fs::{read_to_string, OpenOptions, read_dir};
use std::io::Write;

fn main() {
    
    static_vcruntime::metabuild();
    let export_file_path = env::var("EXPORTS_FILE")
        .expect("No EXPORTS_FILE ?");
    let mut out_file = env::var("OUT_DIR").unwrap();

    if cfg!(windows) {
        out_file.push_str("/proxy.c");

        let mut data_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&out_file)
            .expect("Failed :(");

        for l in read_to_string(&export_file_path).unwrap().lines() {
            let line = format!(
                "#pragma comment(linker, \"/export:{}\")\n",
                l.replace(" @", ",@")
            );
            data_file.write(line.as_bytes()).expect("failed writing");
        }
    } else if cfg!(target_env = "gnu") {
        out_file.push_str("/proxy.def");

        let mut data_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&out_file)
            .expect("Failed :(");

            data_file.write("EXPORTS\n".as_bytes()).expect("failed writing .def headers");
            
            for l in read_to_string(&export_file_path).unwrap().lines() {
                
                data_file.write(format!("{}\n", l).as_bytes()).expect("failed writing");
            }
    }


    if cfg!(target_env = "msvc"){
        cc::Build::new().file(&out_file).compile("proxy");
        for f in read_dir(env::var("OUT_DIR").unwrap()).unwrap() {
            let file_name = f.unwrap().file_name();
            let file_name = file_name.to_string_lossy();
            if file_name.ends_with(".o"){

                println!("cargo:rustc-link-arg={}", file_name)
            }
        }        
    } else if cfg!(target_env = "gnu") {        
        println!("cargo:rustc-link-arg={}", out_file);
    }


    println!("cargo:rustc-env=OUTPUT_PATH={}", env::var("OUTPUT_PATH").expect("No OUTPUT_PATH ?"));

}
