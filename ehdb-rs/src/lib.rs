use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bytes::BytesMut;
use fallible_iterator::FallibleIterator;
use hmac::{Hmac, Mac};
use postgres_protocol::authentication::md5_hash;
use postgres_protocol::message::{backend, frontend};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::io::{self, Read, Write};
use std::slice;
use std::str;
use time::macros::format_description;
use time::OffsetDateTime;
use url::Url;

#[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

#[cfg(target_arch = "wasm32")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "wasmedge_host")]
extern "C" {
    fn host_log(level: i32, ptr: i32, len: i32) -> i32;
    fn host_progress(percent: i32, ptr: i32, len: i32) -> i32;
    fn host_call(op: i32, req_ptr: i32, req_len: i32) -> i32;
    fn host_response_len() -> i32;
    fn host_response_read(dst_ptr: i32, dst_len: i32) -> i32;
    fn host_last_error_len() -> i32;
    fn host_last_error_read(dst_ptr: i32, dst_len: i32) -> i32;
}

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
#[link(wasm_import_module = "wasmedge_host")]
extern "C" {
    fn host_tcp_connect(host_ptr: i32, host_len: i32, port: i32, timeout_ms: i32) -> i32;
    fn host_tcp_read(handle: i32, dst_ptr: i32, dst_len: i32, timeout_ms: i32) -> i32;
    fn host_tcp_write(handle: i32, src_ptr: i32, src_len: i32, timeout_ms: i32) -> i32;
    fn host_tcp_close(handle: i32) -> i32;
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_log(_: i32, _: i32, _: i32) -> i32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_progress(_: i32, _: i32, _: i32) -> i32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_call(_: i32, _: i32, _: i32) -> i32 {
    1
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_response_len() -> i32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_response_read(_: i32, _: i32) -> i32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_last_error_len() -> i32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_last_error_read(_: i32, _: i32) -> i32 {
    0
}

#[cfg(not(all(target_arch = "wasm32", not(target_os = "wasi"))))]
#[allow(dead_code)]
unsafe fn host_tcp_connect(_: i32, _: i32, _: i32, _: i32) -> i32 {
    -1
}

#[cfg(not(all(target_arch = "wasm32", not(target_os = "wasi"))))]
#[allow(dead_code)]
unsafe fn host_tcp_read(_: i32, _: i32, _: i32, _: i32) -> i32 {
    -1
}

#[cfg(not(all(target_arch = "wasm32", not(target_os = "wasi"))))]
#[allow(dead_code)]
unsafe fn host_tcp_write(_: i32, _: i32, _: i32, _: i32) -> i32 {
    -1
}

#[cfg(not(all(target_arch = "wasm32", not(target_os = "wasi"))))]
#[allow(dead_code)]
unsafe fn host_tcp_close(_: i32) -> i32 {
    0
}

thread_local! {
    static STATE: RefCell<PluginState> = RefCell::new(PluginState::default());
    static SCRAM_NONCE_SEQ: RefCell<u64> = const { RefCell::new(1) };
}

#[cfg(target_arch = "wasm32")]
static GETRANDOM_FALLBACK_STATE: AtomicU64 = AtomicU64::new(0x4d59_5df4_d0f3_3173);

#[cfg(target_arch = "wasm32")]
#[no_mangle]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    if dest.is_null() || len == 0 {
        return Ok(());
    }

    let buf = unsafe { slice::from_raw_parts_mut(dest, len) };
    let mut state = GETRANDOM_FALLBACK_STATE.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
        ^ ((dest as usize) as u64)
        ^ ((len as u64) << 32);

    for byte in buf.iter_mut() {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        *byte = state as u8;
    }

    Ok(())
}

#[derive(Default)]
struct PluginState {
    info: Vec<u8>,
    result: Vec<u8>,
    error: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct PluginInput {
    #[serde(rename = "pluginType", default)]
    plugin_type: String,
    #[serde(rename = "targetType", default)]
    target_type: String,
    #[serde(rename = "targetId", default)]
    target_id: String,
    #[serde(rename = "oneshotParam", default)]
    oneshot_param: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    metadata: Value,
}

#[derive(Debug, Deserialize)]
struct TankoubonArchivesResponse {
    #[serde(default)]
    archive_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ArchiveMetadataResponse {
    #[serde(default)]
    archive_id: String,
    #[serde(default)]
    metadata: Value,
}

#[derive(Clone, Debug)]
struct EhdbCandidate {
    gid: String,
    token: String,
    title: String,
    title_alt: String,
    score: i64,
    posted: String,
    cover: String,
}

#[derive(Clone, Debug)]
struct GalleryMatch {
    gid: String,
    token: String,
    title: String,
    title_jpn: String,
}

#[derive(Clone, Debug)]
struct SearchPayload {
    tags_csv: String,
    title: String,
    updated_at: String,
}

#[derive(Clone, Debug)]
struct QueryRow {
    values: HashMap<String, String>,
}

#[derive(Clone, Debug)]
struct PgConfig {
    host: String,
    port: u16,
    user: String,
    password: String,
    database: String,
    application_name: String,
    connect_timeout_ms: i32,
}

#[derive(Clone, Debug)]
struct TitleSearchContext {
    core: String,
    keywords: Vec<String>,
    artist: String,
}

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
#[derive(Clone, Debug)]
struct HostTcpStream {
    handle: i32,
    timeout_ms: i32,
    closed: bool,
}

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
impl HostTcpStream {
    fn connect(host: &str, port: u16, timeout_ms: i32) -> Result<Self, String> {
        let rc = unsafe {
            host_tcp_connect(
                host.as_ptr() as i32,
                host.len() as i32,
                i32::from(port),
                timeout_ms,
            )
        };
        if rc < 0 {
            return Err(HostBridge::read_error());
        }
        Ok(Self {
            handle: rc,
            timeout_ms,
            closed: false,
        })
    }

    fn close(&mut self) {
        if self.closed || self.handle < 0 {
            return;
        }
        let _ = unsafe { host_tcp_close(self.handle) };
        self.closed = true;
    }
}

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
impl Drop for HostTcpStream {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
impl Read for HostTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Ok(0);
        }
        let rc = unsafe {
            host_tcp_read(
                self.handle,
                buf.as_mut_ptr() as i32,
                buf.len() as i32,
                self.timeout_ms,
            )
        };
        if rc < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                HostBridge::read_error(),
            ));
        }
        Ok(rc as usize)
    }
}

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
impl Write for HostTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "socket already closed",
            ));
        }
        let rc = unsafe {
            host_tcp_write(
                self.handle,
                buf.as_ptr() as i32,
                buf.len() as i32,
                self.timeout_ms,
            )
        };
        if rc < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                HostBridge::read_error(),
            ));
        }
        Ok(rc as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
#[derive(Debug)]
struct HostTcpStream {
    stream: TcpStream,
}

#[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
impl HostTcpStream {
    fn connect(host: &str, port: u16, timeout_ms: i32) -> Result<Self, String> {
        let addr = resolve_socket_addr(host, port)?;
        let timeout = std::time::Duration::from_millis(timeout_ms.max(1) as u64);
        let stream = TcpStream::connect_timeout(&addr, timeout).map_err(io_err)?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        let _ = stream.set_nodelay(true);
        Ok(Self { stream })
    }

    fn close(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
impl Read for HostTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

#[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
impl Write for HostTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

struct PgClient {
    stream: HostTcpStream,
    read_buf: BytesMut,
}

impl PgClient {
    fn connect(config: &PgConfig) -> Result<Self, String> {
        let stream = HostTcpStream::connect(&config.host, config.port, config.connect_timeout_ms)?;
        let mut client = Self {
            stream,
            read_buf: BytesMut::with_capacity(16 * 1024),
        };
        client.startup(config)?;
        Ok(client)
    }

    fn startup(&mut self, config: &PgConfig) -> Result<(), String> {
        let mut out = BytesMut::new();
        frontend::startup_message(
            [
                ("user", config.user.as_str()),
                ("database", config.database.as_str()),
                ("application_name", config.application_name.as_str()),
                ("client_encoding", "UTF8"),
            ],
            &mut out,
        )
        .map_err(io_err)?;
        self.write_all(&out)?;

        let mut scram: Option<ScramSession> = None;
        loop {
            match self.read_message()? {
                backend::Message::AuthenticationOk => {}
                backend::Message::AuthenticationCleartextPassword => {
                    let mut msg = BytesMut::new();
                    frontend::password_message(config.password.as_bytes(), &mut msg)
                        .map_err(io_err)?;
                    self.write_all(&msg)?;
                }
                backend::Message::AuthenticationMd5Password(body) => {
                    let password = md5_hash(
                        config.user.as_bytes(),
                        config.password.as_bytes(),
                        body.salt(),
                    );
                    let mut msg = BytesMut::new();
                    frontend::password_message(password.as_bytes(), &mut msg).map_err(io_err)?;
                    self.write_all(&msg)?;
                }
                backend::Message::AuthenticationSasl(body) => {
                    let mut found_scram = false;
                    let mut mechanisms = body.mechanisms();
                    while let Some(mechanism) = mechanisms.next().map_err(io_err)? {
                        if mechanism == "SCRAM-SHA-256" {
                            found_scram = true;
                            break;
                        }
                    }
                    if !found_scram {
                        return Err("database requires unsupported SASL mechanism".to_string());
                    }
                    let session = ScramSession::new(config.password.as_bytes());
                    let initial = session.initial_message();
                    let mut msg = BytesMut::new();
                    frontend::sasl_initial_response("SCRAM-SHA-256", &initial, &mut msg)
                        .map_err(io_err)?;
                    self.write_all(&msg)?;
                    scram = Some(session);
                }
                backend::Message::AuthenticationSaslContinue(body) => {
                    let session = scram
                        .as_mut()
                        .ok_or_else(|| "unexpected SCRAM continuation".to_string())?;
                    session.update(body.data())?;
                    let mut msg = BytesMut::new();
                    frontend::sasl_response(session.client_final_message(), &mut msg)
                        .map_err(io_err)?;
                    self.write_all(&msg)?;
                }
                backend::Message::AuthenticationSaslFinal(body) => {
                    let session = scram
                        .as_mut()
                        .ok_or_else(|| "unexpected SCRAM final".to_string())?;
                    session.finish(body.data())?;
                }
                backend::Message::ParameterStatus(_) => {}
                backend::Message::BackendKeyData(_) => {}
                backend::Message::NoticeResponse(body) => {
                    HostBridge::log(
                        1,
                        &format!("pg notice: {}", format_pg_fields(body.fields())),
                    );
                }
                backend::Message::ReadyForQuery(_) => return Ok(()),
                backend::Message::ErrorResponse(body) => {
                    return Err(format!(
                        "database startup failed: {}",
                        format_pg_fields(body.fields())
                    ));
                }
                other => {
                    return Err(format!(
                        "unexpected database startup message: {}",
                        backend_tag_name(&other)
                    ));
                }
            }
        }
    }

    fn query_rows(&mut self, sql: &str) -> Result<Vec<QueryRow>, String> {
        let mut out = BytesMut::new();
        frontend::query(sql, &mut out).map_err(io_err)?;
        self.write_all(&out)?;

        let mut columns = Vec::<String>::new();
        let mut rows = Vec::<QueryRow>::new();
        loop {
            match self.read_message()? {
                backend::Message::RowDescription(body) => {
                    columns.clear();
                    let mut fields = body.fields();
                    while let Some(field) = fields.next().map_err(io_err)? {
                        columns.push(field.name().to_string());
                    }
                }
                backend::Message::DataRow(body) => {
                    let mut values = HashMap::with_capacity(columns.len());
                    let data = body.buffer();
                    let mut ranges = body.ranges();
                    let mut idx = 0usize;
                    while let Some(range) = ranges.next().map_err(io_err)? {
                        let key = columns
                            .get(idx)
                            .cloned()
                            .unwrap_or_else(|| format!("col_{idx}"));
                        let value = match range {
                            Some(range) => String::from_utf8_lossy(&data[range]).to_string(),
                            None => String::new(),
                        };
                        values.insert(key, value);
                        idx += 1;
                    }
                    rows.push(QueryRow { values });
                }
                backend::Message::CommandComplete(_) => {}
                backend::Message::EmptyQueryResponse => {}
                backend::Message::NoticeResponse(body) => {
                    HostBridge::log(
                        1,
                        &format!("pg notice: {}", format_pg_fields(body.fields())),
                    );
                }
                backend::Message::ReadyForQuery(_) => return Ok(rows),
                backend::Message::ErrorResponse(body) => {
                    return Err(format!("query failed: {}", format_pg_fields(body.fields())));
                }
                other => {
                    return Err(format!(
                        "unexpected query message: {}",
                        backend_tag_name(&other)
                    ));
                }
            }
        }
    }

    fn terminate(&mut self) {
        let mut out = BytesMut::new();
        frontend::terminate(&mut out);
        let _ = self.write_all(&out);
        self.stream.close();
    }

    fn read_message(&mut self) -> Result<backend::Message, String> {
        loop {
            if let Some(message) = backend::Message::parse(&mut self.read_buf).map_err(io_err)? {
                return Ok(message);
            }
            let mut chunk = [0u8; 8192];
            let n = self.stream.read(&mut chunk).map_err(io_err)?;
            if n == 0 {
                return Err("unexpected EOF from database".to_string());
            }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn write_all(&mut self, data: &[u8]) -> Result<(), String> {
        self.stream.write_all(data).map_err(io_err)
    }
}

impl Drop for PgClient {
    fn drop(&mut self) {
        self.terminate();
    }
}

struct ScramSession {
    password: Vec<u8>,
    client_nonce: String,
    client_first_bare: String,
    client_final_without_proof: String,
    auth_message: String,
    server_signature: Vec<u8>,
}

impl ScramSession {
    fn new(password: &[u8]) -> Self {
        let client_nonce = next_scram_nonce();
        let client_first_bare = format!("n=,r={client_nonce}");
        Self {
            password: normalize_password(password),
            client_nonce,
            client_first_bare,
            client_final_without_proof: String::new(),
            auth_message: String::new(),
            server_signature: Vec::new(),
        }
    }

    fn initial_message(&self) -> Vec<u8> {
        format!("y,,{}", self.client_first_bare).into_bytes()
    }

    fn client_final_message(&self) -> &[u8] {
        self.client_final_without_proof.as_bytes()
    }

    fn update(&mut self, server_first_message: &[u8]) -> Result<(), String> {
        let server_first = str::from_utf8(server_first_message)
            .map_err(|e| format!("invalid SCRAM message: {e}"))?;
        let parsed = parse_scram_fields(server_first)?;
        let server_nonce = parsed
            .get("r")
            .ok_or_else(|| "SCRAM server nonce missing".to_string())?;
        if !server_nonce.starts_with(&self.client_nonce) {
            return Err("SCRAM server nonce mismatch".to_string());
        }
        let salt_b64 = parsed
            .get("s")
            .ok_or_else(|| "SCRAM salt missing".to_string())?;
        let iterations = parsed
            .get("i")
            .ok_or_else(|| "SCRAM iteration count missing".to_string())?
            .parse::<u32>()
            .map_err(|e| format!("invalid SCRAM iteration count: {e}"))?;
        let salt = BASE64
            .decode(salt_b64.as_bytes())
            .map_err(|e| format!("invalid SCRAM salt: {e}"))?;
        let salted_password = hi(&self.password, &salt, iterations);

        let mut client_key_mac =
            Hmac::<Sha256>::new_from_slice(&salted_password).map_err(|e| e.to_string())?;
        client_key_mac.update(b"Client Key");
        let client_key = client_key_mac.finalize().into_bytes();

        let stored_key = Sha256::digest(client_key);
        let cbind_input = BASE64.encode(b"y,,");
        let client_final_without_proof = format!("c={cbind_input},r={server_nonce}");
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_without_proof
        );

        let mut client_signature_mac =
            Hmac::<Sha256>::new_from_slice(&stored_key).map_err(|e| e.to_string())?;
        client_signature_mac.update(auth_message.as_bytes());
        let client_signature = client_signature_mac.finalize().into_bytes();

        let mut client_proof = client_key.to_vec();
        for (proof, signature) in client_proof.iter_mut().zip(client_signature.iter()) {
            *proof ^= signature;
        }

        let mut server_key_mac =
            Hmac::<Sha256>::new_from_slice(&salted_password).map_err(|e| e.to_string())?;
        server_key_mac.update(b"Server Key");
        let server_key = server_key_mac.finalize().into_bytes();
        let mut server_signature_mac =
            Hmac::<Sha256>::new_from_slice(&server_key).map_err(|e| e.to_string())?;
        server_signature_mac.update(auth_message.as_bytes());

        self.server_signature = server_signature_mac.finalize().into_bytes().to_vec();
        self.auth_message = auth_message;
        self.client_final_without_proof = format!(
            "{client_final_without_proof},p={}",
            BASE64.encode(client_proof)
        );
        Ok(())
    }

    fn finish(&self, server_final_message: &[u8]) -> Result<(), String> {
        let server_final = str::from_utf8(server_final_message)
            .map_err(|e| format!("invalid SCRAM final: {e}"))?;
        let parsed = parse_scram_fields(server_final)?;
        if let Some(error) = parsed.get("e") {
            return Err(format!("database SCRAM error: {error}"));
        }
        let signature_b64 = parsed
            .get("v")
            .ok_or_else(|| "SCRAM final verifier missing".to_string())?;
        let signature = BASE64
            .decode(signature_b64.as_bytes())
            .map_err(|e| format!("invalid SCRAM verifier: {e}"))?;
        if signature != self.server_signature {
            return Err("SCRAM server signature mismatch".to_string());
        }
        Ok(())
    }
}

struct HostBridge;

impl HostBridge {
    fn log(level: i32, message: &str) {
        unsafe {
            let _ = host_log(level, message.as_ptr() as i32, message.len() as i32);
        }
    }

    fn progress(percent: i32, message: &str) {
        unsafe {
            let _ = host_progress(percent, message.as_ptr() as i32, message.len() as i32);
        }
    }

    fn call(method: &str, params: Value) -> Result<Value, String> {
        let req = json!({
            "method": method,
            "params": params,
        });
        let req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        let rc = unsafe { host_call(0, req_bytes.as_ptr() as i32, req_bytes.len() as i32) };
        if rc != 0 {
            return Err(Self::read_error());
        }
        Self::read_response()
    }

    fn call_typed<T: DeserializeOwned>(method: &str, params: Value) -> Result<T, String> {
        let value = Self::call(method, params)?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    fn read_response() -> Result<Value, String> {
        let len = unsafe { host_response_len() };
        if len < 0 {
            return Err("host_response_len returned negative length".to_string());
        }
        if len == 0 {
            return Ok(Value::Null);
        }
        let mut buf = vec![0u8; len as usize];
        let read = unsafe { host_response_read(buf.as_mut_ptr() as i32, len) };
        if read < 0 {
            return Err("host_response_read failed".to_string());
        }
        serde_json::from_slice(&buf[..read as usize]).map_err(|e| e.to_string())
    }

    fn read_error() -> String {
        let len = unsafe { host_last_error_len() };
        if len <= 0 {
            return "host call failed".to_string();
        }
        let mut buf = vec![0u8; len as usize];
        let read = unsafe { host_last_error_read(buf.as_mut_ptr() as i32, len) };
        if read <= 0 {
            return "host call failed".to_string();
        }
        String::from_utf8_lossy(&buf[..read as usize]).to_string()
    }

    fn list_tankoubon_archives(tankoubon_id: &str) -> Result<Vec<String>, String> {
        let response: TankoubonArchivesResponse = Self::call_typed(
            "tankoubon.list_archives",
            json!({ "tankoubon_id": tankoubon_id }),
        )?;
        Ok(response.archive_ids)
    }

    fn get_archive_metadata(archive_id: &str) -> Result<Value, String> {
        let response: ArchiveMetadataResponse =
            Self::call_typed("archive.get_metadata", json!({ "archive_id": archive_id }))?;
        let _ = response.archive_id;
        Ok(response.metadata)
    }

    fn select_index(
        title: &str,
        options: Vec<Value>,
        message: &str,
        default_index: i32,
        timeout_seconds: i32,
    ) -> Result<usize, String> {
        let response = Self::call(
            "ui.select",
            json!({
                "title": title,
                "message": message,
                "default_index": default_index,
                "timeout_seconds": timeout_seconds,
                "options": options,
            }),
        )?;
        let index = response
            .get("index")
            .and_then(Value::as_i64)
            .ok_or_else(|| "ui.select returned missing index".to_string())?;
        usize::try_from(index).map_err(|_| "ui.select returned invalid index".to_string())
    }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_alloc(size: i32) -> i32 {
    if size <= 0 {
        return 0;
    }
    let layout = Layout::from_size_align(size as usize, 8).unwrap();
    unsafe { alloc(layout) as i32 }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_free(ptr: i32, size: i32) {
    if ptr == 0 || size <= 0 {
        return;
    }
    let layout = Layout::from_size_align(size as usize, 8).unwrap();
    unsafe { dealloc(ptr as *mut u8, layout) }
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_info() -> i32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        ensure_info_bytes(&mut state);
        state.info.as_ptr() as i32
    })
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_info_len() -> i32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        ensure_info_bytes(&mut state);
        state.info.len() as i32
    })
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_run(input_ptr: i32, input_len: i32) -> i32 {
    clear_runtime_buffers();
    let input_bytes = unsafe { read_guest_bytes(input_ptr, input_len) };
    let input = match serde_json::from_slice::<PluginInput>(input_bytes) {
        Ok(v) => v,
        Err(e) => return set_error_and_zero(format!("invalid plugin input: {e}")),
    };

    let payload = build_result_payload(input);
    let result = match serde_json::to_vec(&payload) {
        Ok(v) => v,
        Err(e) => return set_error_and_zero(format!("failed to encode result: {e}")),
    };

    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result = result;
        state.result.as_ptr() as i32
    })
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_result_len() -> i32 {
    STATE.with(|state| state.borrow().result.len() as i32)
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_last_error() -> i32 {
    STATE.with(|state| state.borrow().error.as_ptr() as i32)
}

#[no_mangle]
pub extern "C" fn lanlu_plugin_last_error_len() -> i32 {
    STATE.with(|state| state.borrow().error.len() as i32)
}

fn plugin_info_json() -> Value {
    let runtime = if cfg!(all(target_arch = "wasm32", target_os = "wasi")) {
        "wasmedge"
    } else {
        "wamr"
    };
    let mut permissions = vec![
        "metadata.read_input",
        "archive.get_metadata",
        "tankoubon.list_archives",
        "ui.select",
        "log.write",
        "progress.report",
    ];
    if cfg!(not(all(target_arch = "wasm32", target_os = "wasi"))) {
        permissions.push("tcp.connect");
    }

    json!({
        "name": "EHDB (Rust/WASM)",
        "type": "metadata",
        "namespace": "ehdb",
        "author": "codex",
        "version": "0.1.0",
        "description": "Rust/WASM port of the EHDB metadata plugin.",
        "parameters": [
            {"name": "connection_string", "type": "string", "desc": "PostgreSQL connection string (sslmode=disable only)"}
        ],
        "permissions": permissions,
        "oneshot_arg": "Gallery URL or GID/Token (Will match this exact gallery)",
        "cooldown": 0,
        "runtime": runtime,
        "abi_version": 1
    })
}

#[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    let mut addrs = format!("{host}:{port}").to_socket_addrs().map_err(io_err)?;
    addrs
        .next()
        .ok_or_else(|| format!("failed to resolve host: {host}:{port}"))
}

fn build_result_payload(input: PluginInput) -> Value {
    match execute_plugin(input) {
        Ok(data) => json!({
            "success": true,
            "data": data,
        }),
        Err(error) => json!({
            "success": false,
            "error": error,
        }),
    }
}

fn execute_plugin(input: PluginInput) -> Result<Value, String> {
    if !input.plugin_type.trim().eq_ignore_ascii_case("metadata") {
        return Err("ehdb-rs only supports Metadata plugins".to_string());
    }

    let target_id = input.target_id.trim();
    if target_id.is_empty() {
        return Err("Missing targetId".to_string());
    }

    let connection_string = read_string_param(&input.params, "connection_string")
        .ok_or_else(|| "Connection string is required".to_string())?;
    let config = parse_connection_string(&connection_string)?;
    let mut client = PgClient::connect(&config)?;

    HostBridge::progress(5, "初始化数据库连接...");
    let target_type = normalized_target_type(&input.target_type, &input.params);
    let metadata = ensure_metadata_object(input.metadata);
    let result = if target_type == "tankoubon" || target_type == "tank" {
        HostBridge::progress(35, "处理合集成员...");
        run_collection_mode(&mut client, target_id, metadata)?
    } else {
        HostBridge::progress(35, "开始搜索画廊...");
        run_archive_mode(&mut client, target_id, input.oneshot_param.trim(), metadata)?
    };
    HostBridge::progress(100, "元数据获取完成");
    Ok(result)
}

fn run_archive_mode(
    client: &mut PgClient,
    archive_id: &str,
    oneshot_param: &str,
    mut metadata: Map<String, Value>,
) -> Result<Value, String> {
    let search_payload = build_search_payload(
        client,
        archive_id,
        metadata_string(&metadata, "title"),
        metadata_tags_to_csv(metadata.get("tags")),
        oneshot_param,
    )?;

    if !search_payload.title.is_empty() {
        metadata.insert("title".to_string(), Value::String(search_payload.title));
    }
    metadata.insert(
        "tags".to_string(),
        Value::Array(
            metadata_tags_from_csv(&search_payload.tags_csv)
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    if !search_payload.updated_at.is_empty() {
        metadata.insert(
            "updated_at".to_string(),
            Value::String(search_payload.updated_at),
        );
    }
    metadata.insert("children".to_string(), Value::Array(vec![]));
    metadata.remove("archive");
    metadata.remove("archive_id");
    Ok(Value::Object(metadata))
}

fn run_collection_mode(
    client: &mut PgClient,
    tankoubon_id: &str,
    mut root_metadata: Map<String, Value>,
) -> Result<Value, String> {
    let archive_ids = HostBridge::list_tankoubon_archives(tankoubon_id)?
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>();
    if archive_ids.is_empty() {
        return Err(format!(
            "No member archives found in collection {tankoubon_id}"
        ));
    }

    let mut children = Vec::<Value>::with_capacity(archive_ids.len());
    for (index, archive_id) in archive_ids.iter().enumerate() {
        let percent = 10 + (((index + 1) * 80) / archive_ids.len()) as i32;
        HostBridge::progress(
            percent.min(95),
            &format!("处理合集成员 {}/{}", index + 1, archive_ids.len()),
        );

        let archive_metadata =
            ensure_metadata_object(HostBridge::get_archive_metadata(archive_id)?);
        let search_payload = build_search_payload(
            client,
            archive_id,
            metadata_string(&archive_metadata, "title"),
            metadata_tags_to_csv(archive_metadata.get("tags")),
            "",
        )?;

        let mut patch = Map::<String, Value>::new();
        patch.insert(
            "title".to_string(),
            Value::String(if !search_payload.title.is_empty() {
                search_payload.title
            } else {
                metadata_string(&archive_metadata, "title")
            }),
        );
        patch.insert("type".to_string(), Value::from(0));
        patch.insert(
            "description".to_string(),
            Value::String(metadata_string(&archive_metadata, "description")),
        );
        patch.insert(
            "tags".to_string(),
            Value::Array(
                metadata_tags_from_csv(&search_payload.tags_csv)
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        if !search_payload.updated_at.is_empty() {
            patch.insert(
                "updated_at".to_string(),
                Value::String(search_payload.updated_at),
            );
        }
        patch.insert(
            "assets".to_string(),
            archive_metadata
                .get("assets")
                .cloned()
                .unwrap_or_else(|| Value::Array(vec![])),
        );
        patch.insert("volume_no".to_string(), Value::from((index + 1) as i64));
        patch.insert("entity_id".to_string(), Value::String(archive_id.clone()));
        patch.insert(
            "locator".to_string(),
            json!({
                "entity_type": "archive",
                "entity_id": archive_id,
                "volume_no": (index + 1) as i64,
            }),
        );
        children.push(Value::Object(patch));
    }

    root_metadata.insert("children".to_string(), Value::Array(children));
    root_metadata.remove("archive");
    root_metadata.remove("archive_id");
    Ok(Value::Object(root_metadata))
}

fn build_search_payload(
    client: &mut PgClient,
    archive_id: &str,
    archive_title: String,
    existing_tags: String,
    oneshot_param: &str,
) -> Result<SearchPayload, String> {
    let exact = extract_exact_gallery(oneshot_param)
        .or_else(|| extract_exact_gallery_from_source_tags(&existing_tags));

    let gallery = match exact {
        Some(gallery) => gallery,
        None => lookup_gallery_by_title_and_tags(client, &archive_title, &existing_tags)?,
    };
    if gallery.gid.is_empty() {
        return Err("No matching gallery found in database".to_string());
    }

    let search_data = get_gallery_tags(client, &gallery.gid)?;
    let mut tags = search_data.tags_csv;
    if !tags.is_empty() {
        if !tags.ends_with(',') {
            tags.push(',');
        }
        if !tags.ends_with(' ') {
            tags.push(' ');
        }
    }
    tags.push_str(&format!(
        "source:https://exhentai.org/g/{}/{}, source:https://e-hentai.org/g/{}/{}",
        gallery.gid, gallery.token, gallery.gid, gallery.token
    ));

    let _ = archive_id;
    Ok(SearchPayload {
        tags_csv: tags,
        title: if !search_data.title.is_empty() {
            search_data.title
        } else if !gallery.title_jpn.is_empty() {
            gallery.title_jpn
        } else {
            gallery.title
        },
        updated_at: search_data.updated_at,
    })
}

fn lookup_gallery_by_title_and_tags(
    client: &mut PgClient,
    title: &str,
    existing_tags: &str,
) -> Result<GalleryMatch, String> {
    let context = preprocess_title(title);
    let artist = extract_artist_tag(existing_tags).unwrap_or_else(|| context.artist.clone());

    if let Some(found) = search_by_full_text(client, &context, &artist)? {
        return Ok(found);
    }
    if !context.keywords.is_empty() {
        if let Some(found) = search_by_keywords(client, &context.keywords, &artist)? {
            return Ok(found);
        }
    }
    if context.core.chars().count() >= 4 {
        if let Some(found) = search_by_trigram(client, &context.core, &artist)? {
            return Ok(found);
        }
    }
    Err("No gallery found in database".to_string())
}

fn search_by_full_text(
    client: &mut PgClient,
    context: &TitleSearchContext,
    artist: &str,
) -> Result<Option<GalleryMatch>, String> {
    if has_japanese(&context.core) {
        return Ok(None);
    }
    let words = context
        .core
        .split(|c: char| c.is_whitespace() || c == '-' || c == '_')
        .filter(|word| word.chars().count() >= 2)
        .map(|word| {
            word.chars()
                .filter(|ch| !matches!(ch, '\'' | '"' | '\\'))
                .collect::<String>()
        })
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    if words.is_empty() {
        return Ok(None);
    }
    let tsquery = words.join(" & ");
    if let Some(found) = query_candidate_rows(
        client,
        &build_fulltext_query(&tsquery, artist),
        &context.core,
    )? {
        return Ok(Some(found));
    }
    Ok(None)
}

fn search_by_keywords(
    client: &mut PgClient,
    keywords: &[String],
    artist: &str,
) -> Result<Option<GalleryMatch>, String> {
    if keywords.is_empty() {
        return Ok(None);
    }
    if let Some(found) = query_candidate_rows(
        client,
        &build_keywords_query(keywords, artist),
        &keywords.join(" "),
    )? {
        return Ok(Some(found));
    }
    Ok(None)
}

fn search_by_trigram(
    client: &mut PgClient,
    core: &str,
    artist: &str,
) -> Result<Option<GalleryMatch>, String> {
    if let Some(found) = query_candidate_rows(client, &build_trigram_query(core, artist), core)? {
        return Ok(Some(found));
    }
    Ok(None)
}

fn query_candidate_rows(
    client: &mut PgClient,
    sql: &str,
    input: &str,
) -> Result<Option<GalleryMatch>, String> {
    let rows = client.query_rows(sql)?;
    if rows.is_empty() {
        return Ok(None);
    }
    select_best_match(rows, input).map(Some)
}

fn select_best_match(rows: Vec<QueryRow>, input: &str) -> Result<GalleryMatch, String> {
    let mut ranked = rows
        .into_iter()
        .filter_map(|row| {
            let gid = row_string(&row, "gid");
            let token = row_string(&row, "token");
            if gid.is_empty() || token.is_empty() {
                return None;
            }
            let title = row_string(&row, "title");
            let title_jpn = row_string(&row, "title_jpn");
            Some(EhdbCandidate {
                gid,
                token,
                title: if !title_jpn.is_empty() {
                    title_jpn.clone()
                } else {
                    title.clone()
                },
                title_alt: if !title.is_empty() {
                    title
                } else {
                    title_jpn.clone()
                },
                score: calculate_similarity(input, &row_string(&row, "title"), &title_jpn),
                posted: normalize_posted_value(&row_string(&row, "posted")),
                cover: row_string(&row, "thumb"),
            })
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.gid.cmp(&b.gid)));

    if ranked.is_empty() {
        return Err("No valid gallery rows found".to_string());
    }
    if ranked[0].score < 35 {
        return Err(format!(
            "Best match score ({}) below threshold (35)",
            ranked[0].score
        ));
    }

    let fallback = ranked[0].clone();
    let candidates = ranked
        .into_iter()
        .filter(|item| item.score >= 35)
        .collect::<Vec<_>>();
    let candidates = if candidates.is_empty() {
        vec![fallback]
    } else {
        candidates
    };
    let picked = if candidates.len() == 1 {
        candidates[0].clone()
    } else {
        let options = candidates
            .iter()
            .map(|item| {
                json!({
                    "label": if !item.title.is_empty() { item.title.clone() } else { format!("g/{}", item.gid) },
                    "description": build_candidate_description(item),
                    "cover": item.cover,
                })
            })
            .collect::<Vec<_>>();
        let index = HostBridge::select_index(
            "EHDB Candidate Match",
            options,
            &format!("Select EHDB match for \"{input}\""),
            0,
            120,
        )?;
        candidates
            .get(index)
            .cloned()
            .or_else(|| candidates.first().cloned())
            .ok_or_else(|| "No candidate selected".to_string())?
    };

    Ok(GalleryMatch {
        gid: picked.gid,
        token: picked.token,
        title: picked.title_alt,
        title_jpn: picked.title,
    })
}

fn get_gallery_tags(client: &mut PgClient, gid: &str) -> Result<SearchPayload, String> {
    let sql = format!(
        "SELECT gid::text AS gid, token::text AS token, title::text AS title, title_jpn::text AS title_jpn, \
         category::text AS category, uploader::text AS uploader, posted::text AS posted, tags::text AS tags \
         FROM gallery WHERE gid = {} LIMIT 1",
        sql_numeric_literal(gid)?
    );
    let rows = client.query_rows(&sql)?;
    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| "Gallery not found in database".to_string())?;

    let mut tags = parse_json_string_array(&row_string(&row, "tags"));
    let category = row_string(&row, "category");
    if !category.is_empty() {
        tags.push(format!("category:{}", category.to_ascii_lowercase()));
    }
    let uploader = row_string(&row, "uploader");
    if !uploader.is_empty() {
        tags.push(format!("uploader:{uploader}"));
    }

    Ok(SearchPayload {
        tags_csv: dedup_join_tags(tags),
        title: if !row_string(&row, "title_jpn").is_empty() {
            row_string(&row, "title_jpn")
        } else {
            row_string(&row, "title")
        },
        updated_at: normalize_to_epoch_seconds(&row_string(&row, "posted")),
    })
}

fn parse_connection_string(raw: &str) -> Result<PgConfig, String> {
    let url = Url::parse(raw).map_err(|e| format!("Invalid connection string: {e}"))?;
    let scheme = url.scheme().to_ascii_lowercase();
    if scheme != "postgres" && scheme != "postgresql" {
        return Err("Connection string must use postgres:// or postgresql://".to_string());
    }
    let sslmode = url
        .query_pairs()
        .find(|(key, _)| key.eq_ignore_ascii_case("sslmode"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_else(|| "disable".to_string());
    if sslmode != "disable" {
        return Err("ehdb-rs currently supports sslmode=disable only".to_string());
    }

    let host = url
        .host_str()
        .map(str::to_string)
        .ok_or_else(|| "Connection string host is required".to_string())?;
    let port = url.port().unwrap_or(5432);
    let user = percent_decode(url.username());
    if user.is_empty() {
        return Err("Connection string user is required".to_string());
    }
    let password = url.password().map(percent_decode).unwrap_or_default();
    let database = percent_decode(url.path().trim_start_matches('/'));
    if database.is_empty() {
        return Err("Connection string database is required".to_string());
    }
    let connect_timeout_ms = url
        .query_pairs()
        .find(|(key, _)| key.eq_ignore_ascii_case("connect_timeout"))
        .and_then(|(_, value)| value.parse::<i32>().ok())
        .map(|seconds| seconds.saturating_mul(1000))
        .unwrap_or(15_000);
    let application_name = url
        .query_pairs()
        .find(|(key, _)| key.eq_ignore_ascii_case("application_name"))
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "EhdbPlugin".to_string());

    Ok(PgConfig {
        host,
        port,
        user,
        password,
        database,
        application_name,
        connect_timeout_ms,
    })
}

fn normalized_target_type(target_type: &str, params: &Value) -> String {
    let from_input = target_type.trim().to_ascii_lowercase();
    if !from_input.is_empty() {
        return from_input;
    }
    params
        .get("__target_type")
        .and_then(Value::as_str)
        .unwrap_or("archive")
        .trim()
        .to_ascii_lowercase()
}

fn read_string_param(params: &Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(|value| match value {
            Value::String(v) => Some(v.trim().to_string()),
            Value::Number(v) => Some(v.to_string()),
            Value::Bool(v) => Some(if *v { "1".to_string() } else { "0".to_string() }),
            _ => None,
        })
        .filter(|value| !value.is_empty())
}

fn ensure_metadata_object(metadata: Value) -> Map<String, Value> {
    match metadata {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn metadata_string(metadata: &Map<String, Value>, key: &str) -> String {
    metadata
        .get(key)
        .map(|value| match value {
            Value::String(v) => v.trim().to_string(),
            Value::Number(v) => v.to_string(),
            Value::Bool(v) => {
                if *v {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            _ => String::new(),
        })
        .unwrap_or_default()
}

fn metadata_tags_to_csv(tags: Option<&Value>) -> String {
    match tags {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
            .collect::<Vec<_>>()
            .join(", "),
        Some(Value::String(v)) => v.trim().to_string(),
        _ => String::new(),
    }
}

fn metadata_tags_from_csv(csv: &str) -> Vec<String> {
    let mut seen = BTreeSet::<String>::new();
    for tag in csv.split(',') {
        let normalized = tag.trim();
        if !normalized.is_empty() {
            seen.insert(normalized.to_string());
        }
    }
    seen.into_iter().collect()
}

fn dedup_join_tags(tags: Vec<String>) -> String {
    let mut seen = BTreeSet::<String>::new();
    for tag in tags {
        let normalized = tag.trim();
        if !normalized.is_empty() {
            seen.insert(normalized.to_string());
        }
    }
    seen.into_iter().collect::<Vec<_>>().join(", ")
}

fn extract_exact_gallery(oneshot: &str) -> Option<GalleryMatch> {
    let input = oneshot.trim();
    if input.is_empty() {
        return None;
    }
    extract_gallery_from_text(input)
}

fn extract_exact_gallery_from_source_tags(tags_csv: &str) -> Option<GalleryMatch> {
    for part in tags_csv.split(',') {
        let trimmed = part.trim();
        let source = trimmed
            .strip_prefix("source:")
            .or_else(|| trimmed.strip_prefix("Source:"))
            .unwrap_or(trimmed);
        if let Some(gallery) = extract_gallery_from_text(source.trim()) {
            return Some(gallery);
        }
    }
    None
}

fn extract_gallery_from_text(raw: &str) -> Option<GalleryMatch> {
    let marker = "/g/";
    let lower = raw.to_ascii_lowercase();
    let start = lower.find(marker)?;
    let tail = &raw[start + marker.len()..];
    let mut segments = tail.split('/');
    let gid = segments.next()?.trim();
    let token = segments.next()?.trim();
    if gid.is_empty()
        || token.is_empty()
        || !gid.chars().all(|ch| ch.is_ascii_digit())
        || !token.chars().all(|ch| ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(GalleryMatch {
        gid: gid.to_string(),
        token: token.to_string(),
        title: String::new(),
        title_jpn: String::new(),
    })
}

fn preprocess_title(title: &str) -> TitleSearchContext {
    let mut core = title.trim().to_string();
    let mut artist = String::new();

    while let Some((content, rest)) = strip_leading_bracketed(&core) {
        if looks_like_artist_marker(&content)
            || (artist.is_empty() && looks_like_reasonable_artist(&content))
        {
            artist = content.trim().to_string();
            core = rest.trim_start().to_string();
        } else {
            break;
        }
    }

    core = remove_suffix_markers(&core);
    core = remove_square_brackets(&core);
    core = remove_marked_parentheses(&core);
    core = collapse_spaces(&core);

    let keywords = core
        .split(|c: char| c.is_whitespace() || matches!(c, '-' | '_' | '～' | '~' | '、' | '，'))
        .filter(|token| token.chars().count() >= 2)
        .take(10)
        .map(str::to_string)
        .collect::<Vec<_>>();

    TitleSearchContext {
        core,
        keywords,
        artist,
    }
}

fn calculate_similarity(input: &str, db_title: &str, db_title_jpn: &str) -> i64 {
    let input_lower = input.to_ascii_lowercase();
    let title_lower = db_title.to_ascii_lowercase();
    let title_jpn_lower = db_title_jpn.to_ascii_lowercase();
    let mut score = 0i64;
    if !input_lower.is_empty()
        && (title_lower.contains(&input_lower) || title_jpn_lower.contains(&input_lower))
    {
        score += 50;
    }
    for word in input_lower
        .split(|c: char| c.is_whitespace() || c == '-' || c == '_')
        .filter(|word| word.chars().count() >= 2)
    {
        if title_lower.contains(word) || title_jpn_lower.contains(word) {
            score += 10;
        }
    }
    score
}

fn extract_artist_tag(tags: &str) -> Option<String> {
    for part in tags.split(',') {
        let trimmed = part.trim();
        if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("artist:") {
            let value = trimmed[7..].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn has_japanese(text: &str) -> bool {
    text.chars().any(|ch| {
        ('\u{3040}'..='\u{30ff}').contains(&ch) || ('\u{4e00}'..='\u{9fff}').contains(&ch)
    })
}

fn build_fulltext_query(tsquery: &str, artist: &str) -> String {
    let select = "SELECT gid::text AS gid, token::text AS token, title::text AS title, title_jpn::text AS title_jpn, thumb::text AS thumb, posted::text AS posted FROM gallery";
    let rank_expr = format!(
        "ts_rank(title_tsv, to_tsquery('simple', {}))",
        sql_literal(tsquery)
    );
    let mut query = format!(
        "{select} WHERE title_tsv @@ to_tsquery('simple', {})",
        sql_literal(tsquery)
    );
    if !artist.trim().is_empty() {
        let artist_lower = artist.trim().to_ascii_lowercase();
        query.push_str(&format!(
            " AND (tags @> {}::jsonb OR tags @> {}::jsonb)",
            sql_literal(&serde_json::to_string(&vec![format!("artist:{artist_lower}")]).unwrap()),
            sql_literal(&serde_json::to_string(&vec![format!("group:{artist_lower}")]).unwrap()),
        ));
    }
    query.push_str(&format!(" ORDER BY {rank_expr} DESC, posted DESC LIMIT 10"));
    query
}

fn build_keywords_query(keywords: &[String], artist: &str) -> String {
    let select = "SELECT gid::text AS gid, token::text AS token, title::text AS title, title_jpn::text AS title_jpn, thumb::text AS thumb, posted::text AS posted FROM gallery";
    let conditions = keywords
        .iter()
        .map(|keyword| {
            let pattern = format!("%{keyword}%");
            format!(
                "(title ILIKE {} OR title_jpn ILIKE {})",
                sql_literal(&pattern),
                sql_literal(&pattern)
            )
        })
        .collect::<Vec<_>>()
        .join(" AND ");
    let mut query = format!("{select} WHERE {conditions}");
    if !artist.trim().is_empty() {
        let artist_lower = artist.trim().to_ascii_lowercase();
        query.push_str(&format!(
            " AND (tags @> {}::jsonb OR tags @> {}::jsonb)",
            sql_literal(&serde_json::to_string(&vec![format!("artist:{artist_lower}")]).unwrap()),
            sql_literal(&serde_json::to_string(&vec![format!("group:{artist_lower}")]).unwrap()),
        ));
    }
    query.push_str(" ORDER BY posted DESC LIMIT 10");
    query
}

fn build_trigram_query(core: &str, artist: &str) -> String {
    let select = "SELECT gid::text AS gid, token::text AS token, title::text AS title, title_jpn::text AS title_jpn, thumb::text AS thumb, posted::text AS posted FROM gallery";
    let core_literal = sql_literal(core);
    let mut query =
        format!("{select} WHERE (title % {core_literal} OR title_jpn % {core_literal})");
    if !artist.trim().is_empty() {
        let artist_lower = artist.trim().to_ascii_lowercase();
        query.push_str(&format!(
            " AND (tags @> {}::jsonb OR tags @> {}::jsonb)",
            sql_literal(&serde_json::to_string(&vec![format!("artist:{artist_lower}")]).unwrap()),
            sql_literal(&serde_json::to_string(&vec![format!("group:{artist_lower}")]).unwrap()),
        ));
    }
    query.push_str(&format!(
        " ORDER BY GREATEST(similarity(title, {core_literal}), similarity(title_jpn, {core_literal})) DESC, posted DESC LIMIT 10"
    ));
    query
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sql_numeric_literal(value: &str) -> Result<String, String> {
    if value.chars().all(|ch| ch.is_ascii_digit()) {
        Ok(value.to_string())
    } else {
        Err("gid must be numeric".to_string())
    }
}

fn row_string(row: &QueryRow, key: &str) -> String {
    row.values.get(key).cloned().unwrap_or_default()
}

fn build_candidate_description(candidate: &EhdbCandidate) -> String {
    let mut parts = Vec::<String>::new();
    if !candidate.title_alt.is_empty() && candidate.title_alt != candidate.title {
        parts.push(format!("Original: {}", candidate.title_alt));
    }
    if !candidate.posted.is_empty() {
        parts.push(format!("Posted: {}", candidate.posted));
    }
    parts.push(format!("gid:{}", candidate.gid));
    parts.push(format!("Score: {}", candidate.score));
    parts.join(" | ")
}

fn normalize_posted_value(value: &str) -> String {
    let raw = value.trim();
    if raw.is_empty() {
        return String::new();
    }
    if !raw.chars().all(|ch| ch.is_ascii_digit()) {
        return raw.to_string();
    }
    if raw.len() >= 10 {
        return raw.to_string();
    }
    raw.to_string()
}

fn normalize_to_epoch_seconds(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        let maybe_secs = if trimmed.len() > 12 {
            trimmed[..trimmed.len() - 3].parse::<i64>().ok()
        } else {
            trimmed.parse::<i64>().ok()
        };
        if let Some(secs) = maybe_secs {
            if let Some(ts) = epoch_seconds_to_utc_timestamp(secs) {
                return ts;
            }
        }
        return String::new();
    }
    trimmed.to_string()
}

fn epoch_seconds_to_utc_timestamp(secs: i64) -> Option<String> {
    let fmt = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| dt.format(fmt).ok())
}

fn parse_json_string_array(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default()
}

fn percent_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'%' && idx + 2 < bytes.len() {
            if let (Some(a), Some(b)) = (hex_value(bytes[idx + 1]), hex_value(bytes[idx + 2])) {
                out.push((a * 16 + b) as char);
                idx += 3;
                continue;
            }
        }
        if bytes[idx] == b'+' {
            out.push(' ');
        } else {
            out.push(bytes[idx] as char);
        }
        idx += 1;
    }
    out
}

fn hex_value(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

fn strip_leading_bracketed(input: &str) -> Option<(String, String)> {
    let mut chars = input.char_indices();
    let (_, first) = chars.next()?;
    let close = match first {
        '[' => ']',
        '【' => '】',
        '(' => ')',
        '（' => '）',
        _ => return None,
    };
    let mut depth = 1i32;
    for (idx, ch) in input.char_indices().skip(1) {
        if ch == first {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                let content = input[first.len_utf8()..idx].to_string();
                let rest = input[idx + ch.len_utf8()..].to_string();
                return Some((content, rest));
            }
        }
    }
    None
}

fn looks_like_artist_marker(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    lower.contains("circle")
        || lower.contains("_group")
        || lower.contains("teamauteur")
        || lower.contains("artwork")
        || content.contains("スタジオ")
        || content.contains("イラスト")
}

fn looks_like_reasonable_artist(content: &str) -> bool {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    trimmed
        .chars()
        .any(|ch| ch.is_ascii_alphabetic() || ('\u{3040}'..='\u{9fff}').contains(&ch))
}

fn remove_suffix_markers(input: &str) -> String {
    let mut out = input.to_string();
    let suffix_tokens = [
        "DL",
        "Digital",
        "デジタル",
        "電子",
        "无修正",
        "無修正",
        "中文",
        "汉化",
        "漢化",
        "翻訳",
        "翻译",
        "COMIC",
        "Comiket",
    ];
    for token in suffix_tokens {
        out = out.replace(token, " ");
    }
    for ext in [".zip", ".rar", ".7z", ".cbz", ".cbr"] {
        if out.to_ascii_lowercase().ends_with(ext) {
            out.truncate(out.len() - ext.len());
        }
    }
    out
}

fn remove_square_brackets(input: &str) -> String {
    remove_bracket_pairs(input, &[('[', ']'), ('【', '】')])
}

fn remove_marked_parentheses(input: &str) -> String {
    remove_bracket_pairs(input, &[('(', ')'), ('（', '）')])
}

fn remove_bracket_pairs(input: &str, pairs: &[(char, char)]) -> String {
    let mut out = String::with_capacity(input.len());
    let chars = input.chars().collect::<Vec<_>>();
    let mut idx = 0usize;
    while idx < chars.len() {
        let ch = chars[idx];
        let mut consumed = false;
        for (open, close) in pairs {
            if ch == *open {
                let start = idx + 1;
                let mut end = start;
                let mut depth = 1i32;
                while end < chars.len() {
                    if chars[end] == *open {
                        depth += 1;
                    } else if chars[end] == *close {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    end += 1;
                }
                if end < chars.len() {
                    let content = chars[start..end].iter().collect::<String>();
                    if pairs.len() == 1 && !contains_marked_parenthesis_token(&content) {
                        out.push(ch);
                        out.push_str(&content);
                        out.push(*close);
                    } else {
                        out.push(' ');
                    }
                    idx = end + 1;
                    consumed = true;
                    break;
                }
            }
        }
        if !consumed {
            out.push(ch);
            idx += 1;
        }
    }
    out
}

fn contains_marked_parenthesis_token(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    lower.contains("dl")
        || lower.contains("digital")
        || lower.contains("comic")
        || lower.contains("c0")
        || content.contains("翻訳")
        || content.contains("翻译")
}

fn collapse_spaces(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn next_scram_nonce() -> String {
    SCRAM_NONCE_SEQ.with(|seq| {
        let mut seq = seq.borrow_mut();
        let current = *seq;
        *seq = seq.saturating_add(1);
        let mut nonce = format!("lanluwasm{:016x}", current);
        while nonce.len() < 24 {
            nonce.push(char::from(b'A' + (nonce.len() % 26) as u8));
        }
        nonce
    })
}

fn normalize_password(pass: &[u8]) -> Vec<u8> {
    let Ok(pass) = str::from_utf8(pass) else {
        return pass.to_vec();
    };
    match stringprep::saslprep(pass) {
        Ok(value) => value.into_owned().into_bytes(),
        Err(_) => pass.as_bytes().to_vec(),
    }
}

fn hi(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(password).expect("hmac init");
    mac.update(salt);
    mac.update(&[0, 0, 0, 1]);
    let mut prev = mac.finalize().into_bytes().to_vec();
    let mut out = prev.clone();
    for _ in 1..iterations {
        let mut round = Hmac::<Sha256>::new_from_slice(password).expect("hmac init");
        round.update(&prev);
        prev = round.finalize().into_bytes().to_vec();
        for (lhs, rhs) in out.iter_mut().zip(prev.iter()) {
            *lhs ^= *rhs;
        }
    }
    out
}

fn parse_scram_fields(message: &str) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    for part in message.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| format!("invalid SCRAM field: {part}"))?;
        out.insert(key.to_string(), value.to_string());
    }
    Ok(out)
}

fn format_pg_fields(mut fields: backend::ErrorFields<'_>) -> String {
    let mut message = String::new();
    while let Ok(Some(field)) = fields.next() {
        if field.type_() == b'M' {
            message = String::from_utf8_lossy(field.value_bytes()).to_string();
            break;
        }
    }
    if message.is_empty() {
        "unknown database error".to_string()
    } else {
        message
    }
}

fn backend_tag_name(message: &backend::Message) -> &'static str {
    match message {
        backend::Message::AuthenticationCleartextPassword => "AuthenticationCleartextPassword",
        backend::Message::AuthenticationGss => "AuthenticationGss",
        backend::Message::AuthenticationKerberosV5 => "AuthenticationKerberosV5",
        backend::Message::AuthenticationMd5Password(_) => "AuthenticationMd5Password",
        backend::Message::AuthenticationOk => "AuthenticationOk",
        backend::Message::AuthenticationScmCredential => "AuthenticationScmCredential",
        backend::Message::AuthenticationSspi => "AuthenticationSspi",
        backend::Message::AuthenticationGssContinue(_) => "AuthenticationGssContinue",
        backend::Message::AuthenticationSasl(_) => "AuthenticationSasl",
        backend::Message::AuthenticationSaslContinue(_) => "AuthenticationSaslContinue",
        backend::Message::AuthenticationSaslFinal(_) => "AuthenticationSaslFinal",
        backend::Message::BackendKeyData(_) => "BackendKeyData",
        backend::Message::BindComplete => "BindComplete",
        backend::Message::CloseComplete => "CloseComplete",
        backend::Message::CommandComplete(_) => "CommandComplete",
        backend::Message::CopyData(_) => "CopyData",
        backend::Message::CopyDone => "CopyDone",
        backend::Message::CopyInResponse(_) => "CopyInResponse",
        backend::Message::CopyOutResponse(_) => "CopyOutResponse",
        backend::Message::DataRow(_) => "DataRow",
        backend::Message::EmptyQueryResponse => "EmptyQueryResponse",
        backend::Message::ErrorResponse(_) => "ErrorResponse",
        backend::Message::NoData => "NoData",
        backend::Message::NoticeResponse(_) => "NoticeResponse",
        backend::Message::NotificationResponse(_) => "NotificationResponse",
        backend::Message::ParameterDescription(_) => "ParameterDescription",
        backend::Message::ParameterStatus(_) => "ParameterStatus",
        backend::Message::ParseComplete => "ParseComplete",
        backend::Message::PortalSuspended => "PortalSuspended",
        backend::Message::ReadyForQuery(_) => "ReadyForQuery",
        backend::Message::RowDescription(_) => "RowDescription",
        _ => "Unknown",
    }
}

fn io_err(err: impl ToString) -> String {
    err.to_string()
}

fn clear_runtime_buffers() {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result.clear();
        state.error.clear();
    });
}

fn ensure_info_bytes(state: &mut PluginState) {
    if state.info.is_empty() {
        state.info = serde_json::to_vec(&plugin_info_json()).unwrap_or_else(|_| b"{}".to_vec());
    }
}

fn set_error_and_zero(message: String) -> i32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.result.clear();
        state.error = message.into_bytes();
        0
    })
}

unsafe fn read_guest_bytes(ptr: i32, len: i32) -> &'static [u8] {
    if ptr == 0 || len <= 0 {
        &[]
    } else {
        slice::from_raw_parts(ptr as *const u8, len as usize)
    }
}
