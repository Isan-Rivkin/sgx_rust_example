# Project Title

Pure Rust Enclave && Untrusted in Rust. 


### Prerequisites


* [RUST-SGX-SDK](https://github.com/baidu/rust-sgx-sdk/blob/master/documents/sgxtime.md) - follow the instalation rules
* clone this repo into /some/path/hello_rust_example
* run docker 
``` 
 docker run -v baidu/sdk/repo/path/rust-sgx-sdk/:/root/sgx -v /some/path/hello_rust_example:/root/hello_rust_example -v -ti --device /dev/isgx baiduxlab/sgx-rust
```
* Inside docker: 
```
 /opt/intel/sgxpsw/aesm/aesm_service &
 ```

```
cd /root/hello_rust_example
```

```
make
```

```
cd bin/
```

* Run the binary 

```
./app
```