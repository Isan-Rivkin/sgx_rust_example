// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;

use sgx_urts::SgxEnclave;

use std::io::{Read, Write};
use std::fs;
use std::path;
use std::env;

extern crate base64;
use base64::{encode, decode};
use marker::ContiguousMemory;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
static ENCLAVE_TOKEN: &'static str = "enclave.token";

extern {
    fn say_something(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;
}
extern {
    fn say_something_twice(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;
}

#[link(name = "sgx_tservice")] extern {
    fn ecall_create_report(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, targetInfo : *const sgx_target_info_t,
     report: *mut sgx_report_t) -> sgx_status_t ;
}
#[link(name = "sgx_uae_service")] extern {
    pub fn sgx_init_quote(p_target_info: * mut sgx_target_info_t, p_gid: * mut sgx_epid_group_id_t) -> sgx_status_t;
}
#[link(name = "sgx_uae_service")] extern {
    pub fn sgx_calc_quote_size(p_sig_rl: * const ::uint8_t, sig_rl_size: ::uint32_t, p_quote_size: * mut ::uint32_t) -> sgx_status_t;        
}

#[link(name = "sgx_uae_service")] extern {
    pub fn sgx_get_quote(p_report: * const sgx_report_t,
                         quote_type: sgx_quote_sign_type_t,
                         p_spid: * const sgx_spid_t,
                         p_nonce: * const sgx_quote_nonce_t,
                         p_sig_rl: * const ::uint8_t,
                         sig_rl_size: ::uint32_t,
                         p_qe_report: * mut sgx_report_t,
                         p_quote: * mut sgx_quote_t,
                         quote_size: ::uint32_t) -> sgx_status_t;
}

        
fn init_enclave() -> SgxResult<SgxEnclave> {
    
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // Step 1: try to retrieve the launch token saved by last transaction 
    //         if there is no token, then create a new one.
    // 
    // try to get the token saved in $HOME */
    let mut home_dir = path::PathBuf::new();
    let use_token = match env::home_dir() {
        Some(path) => {
            println!("[+] Home dir is {}", path.display());
            home_dir = path;
            true
        },
        None => {
            println!("[-] Cannot get home dir");
            false
        }
    };

    let token_file: path::PathBuf = home_dir.join(ENCLAVE_TOKEN);;
    if use_token == true {
        match fs::File::open(&token_file) {
            Err(_) => {
                println!("[-] Open token file {} error! Will create one.", token_file.as_path().to_str().unwrap());
            },
            Ok(mut f) => {
                println!("[+] Open token file success! ");
                match f.read(&mut launch_token) {
                    Ok(1024) => {
                        println!("[+] Token file valid!");
                    },
                    _ => println!("[+] Token file invalid, will create new token file"),
                }
            }
        }
    }

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1 
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let enclave = try!(SgxEnclave::create(ENCLAVE_FILE, 
                                          debug, 
                                          &mut launch_token,
                                          &mut launch_token_updated,
                                          &mut misc_attr));
    
    // Step 3: save the launch token if it is updated 
    if use_token == true && launch_token_updated != 0 {
        // reopen the file with write capablity 
        match fs::File::create(&token_file) {
            Ok(mut f) => {
                match f.write_all(&launch_token) {
                    Ok(()) => println!("[+] Saved updated launch token!"),
                    Err(_) => println!("[-] Failed to save updated launch token!"),
                }
            },
            Err(_) => {
                println!("[-] Failed to save updated enclave token, but doesn't matter");
            },
        }
    }

    Ok(enclave)
}
#[allow(unused_variables, unused_mut)]
fn main() { 

    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };

    let input_string = String::from("This is a normal world string passed into Enclave!\n");
    
    let mut retval = sgx_status_t::SGX_SUCCESS; 

    let result = unsafe {
        say_something(enclave.geteid(),
                      &mut retval,
                      input_string.as_ptr() as * const u8,
                      input_string.len())
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    // my tests 

    // test 1 

    let my_input = String::from("This is my normal world string into enclave ");
    retval = sgx_status_t::SGX_SUCCESS;
    
    let result = unsafe {
        say_something_twice(enclave.geteid(),
        &mut retval,
        my_input.as_ptr() as * const u8,
        my_input.len())
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    // test 2 

    let mut stat = sgx_status_t::SGX_SUCCESS; 
    
        let mut targetInfo = sgx_target_info_t::default();
        let mut gid = sgx_epid_group_id_t::default();
        // create quote 
        stat = unsafe{
            sgx_init_quote(&mut targetInfo ,&mut gid)
        };
        println!("init_quote status = {:?}",stat);
        println!("init_quote mr_enclave = {:?}",targetInfo.mr_enclave.m );
        // create report
        let mut report = sgx_report_t::default(); 
        let mut retval : sgx_status_t = sgx_status_t::SGX_SUCCESS;
        stat = unsafe {
            ecall_create_report(enclave.geteid(),&mut retval,&targetInfo,&mut report)
        };
        println!("report.mr_signer  = {:?}",report.body.mr_signer.m );
        // calc quote size  
        let mut quoteSize : u32= 0;
        stat = unsafe {
            sgx_calc_quote_size(std::ptr::null(), 0, &mut quoteSize)
        };
        println!("The quote size status {:?} and its  ==> {:?}",stat,quoteSize );
        // get the actual quote 
        let SGX_UNLINKABLE_SIGNATURE :u32 = 0;
        let quoteType = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;

        // my spid {0x3D,0xDB,0x33,0x8B,0xD5,0x2E,0xE3,0x14,0xB0,0x1F,0x1E,0x4E,0x1E,0x84,0xE8,0xAA};
        let spid =  [0x3D,0xDB,0x33,0x8B,0xD5,0x2E,0xE3,0x14,0xB0,0x1F,0x1E,0x4E,0x1E,0x84,0xE8,0xAA];
        let mut finalSPID : sgx_spid_t = sgx_spid_t{id:spid};
        let mut theQuote = sgx_quote_t::default();
        let nonce =  sgx_quote_nonce_t::default();;
        let mut qeReport = sgx_report_t::default();
        stat = unsafe {
            sgx_get_quote(&report, 
            quoteType , 
            &finalSPID, 
            &nonce,
            std::ptr::null(),
            0, 
            &mut qeReport,
            &mut theQuote, 
            quoteSize )
        };
        println!("=========== the quote ==================");
        println!("get_quote() status = {:?}",stat );
        println!("version {}",theQuote.version );
        println!("get_quote() signature_len = {:?}",theQuote.signature_len );
        println!("get_quote() signature array len  = {:?}",theQuote.signature.len() );
        println!("get_quote() signature   = {:?}",theQuote.signature );
        println!("=========== the quote ==================");

        let bytes: &[u8] = unsafe { any_as_u8_slice(&theQuote) };
        //println!("{:?}", bytes);
        
        let encoded_quote = encode(bytes);
        println!("Encoded Quote = {}",encoded_quote );
    //         pub struct sgx_quote_t {
    //     pub version: ::uint16_t,                    /* 0   */
    //     pub sign_type: ::uint16_t,                  /* 2   */
    //     pub epid_group_id: sgx_epid_group_id_t,     /* 4   */
    //     pub qe_svn: sgx_isv_svn_t,                  /* 8   */
    //     pub pce_svn: sgx_isv_svn_t,                 /* 10  */
    //     pub xeid: ::uint32_t,                       /* 12  */
    //     pub basename: sgx_basename_t,               /* 16  */
    //     pub report_body: sgx_report_body_t,         /* 48  */
    //     pub signature_len: ::uint32_t,              /* 432 */
    //     pub signature: [::uint8_t; 0],              /* 436 */
    // }

    // end of my tests

    println!("[+] say_something success...");

    enclave.destroy();

}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}