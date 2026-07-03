#![cfg(target_os = "android")]

use jni::{
    objects::{GlobalRef, JClass, JValue},
    sys::{jint, JNI_VERSION_1_6},
    JavaVM,
};
use std::ffi::c_void;
use std::sync::OnceLock;

static JVM: OnceLock<JavaVM> = OnceLock::new();
static BRIDGE_CLASS: OnceLock<GlobalRef> = OnceLock::new();

pub fn store_java_vm(vm: JavaVM) {
    let _ = JVM.set(vm);
}

fn store_bridge_class(env: &jni::JNIEnv<'_>, class: JClass<'_>) {
    if BRIDGE_CLASS.get().is_none() {
        if let Ok(class_ref) = env.new_global_ref(&class) {
            let _ = BRIDGE_CLASS.set(class_ref);
        }
    }
}

fn ensure_bridge_class_cached() {
    if BRIDGE_CLASS.get().is_some() {
        return;
    }

    let _ = with_env(|env| {
        let class = env
            .find_class("com/taktaz208/oghabvpn/AndroidVpnBridge")
            .map_err(|error| format!("Android bridge class not found: {error}"))?;
        store_bridge_class(env, class);
        Ok(())
    });
}

#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(vm: *mut jni::sys::JavaVM, _: *mut c_void) -> jint {
    if let Ok(vm) = JavaVM::from_raw(vm) {
        store_java_vm(vm);
    }
    ensure_bridge_class_cached();
    JNI_VERSION_1_6
}

fn with_env<R, F>(f: F) -> Result<R, String>
where
    F: for<'a> FnOnce(&mut jni::JNIEnv<'a>) -> Result<R, String>,
{
    let vm = JVM
        .get()
        .ok_or_else(|| "Android JVM not initialized".to_string())?;
    let mut env = vm
        .attach_current_thread_as_daemon()
        .map_err(|error| format!("Failed to attach JNI thread: {error}"))?;
    f(&mut env)
}

fn bridge_class() -> Result<&'static GlobalRef, String> {
    if BRIDGE_CLASS.get().is_none() {
        ensure_bridge_class_cached();
    }
    BRIDGE_CLASS
        .get()
        .ok_or_else(|| "Android bridge class was not registered before native call".to_string())
}

pub fn call_connect(config: &str, tunnel_mode: bool) -> Result<(), String> {
    with_env(|env| {
        let class = bridge_class()?;
        let config = env
            .new_string(config)
            .map_err(|error| format!("Failed to create config string: {error}"))?;
        let tunnel_mode = JValue::Bool(if tunnel_mode { 1 } else { 0 });
        env.call_static_method(
            class,
            "connect",
            "(Ljava/lang/String;Z)V",
            &[(&config).into(), tunnel_mode],
        )
        .map_err(|error| format!("Android connect failed: {error}"))?;
        Ok(())
    })
}

pub fn call_disconnect() -> Result<(), String> {
    with_env(|env| {
        let class = bridge_class()?;
        env.call_static_method(class, "disconnect", "()V", &[])
            .map_err(|error| format!("Android disconnect failed: {error}"))?;
        Ok(())
    })
}

pub fn call_is_vpn_running() -> Result<bool, String> {
    with_env(|env| {
        let class = bridge_class()?;
        let value = env
            .call_static_method(class, "isVpnRunning", "()Z", &[])
            .map_err(|error| format!("Android VPN status check failed: {error}"))?;
        value
            .z()
            .map_err(|error| format!("Android VPN status decode failed: {error}"))
    })
}

pub fn call_measure_delay(config: &str, url: &str) -> Result<i64, String> {
    with_env(|env| {
        let class = bridge_class()?;
        let config = env
            .new_string(config)
            .map_err(|error| format!("Failed to create config string: {error}"))?;
        let url = env
            .new_string(url)
            .map_err(|error| format!("Failed to create probe url: {error}"))?;
        let value = env
            .call_static_method(
                class,
                "measureOutboundDelay",
                "(Ljava/lang/String;Ljava/lang/String;)J",
                &[(&config).into(), (&url).into()],
            )
            .map_err(|error| format!("Android delay probe failed: {error}"))?;
        value
            .j()
            .map_err(|error| format!("Android delay result decode failed: {error}"))
    })
}

#[no_mangle]
pub extern "system" fn Java_com_taktaz208_oghabvpn_AndroidVpnBridge_nativeRegisterVm(
    env: jni::JNIEnv,
    class: JClass,
) {
    if let Ok(vm) = env.get_java_vm() {
        store_java_vm(vm);
    }
    store_bridge_class(&env, class);
}
