use crate::protocol::keyed_archive::{archive, now_apple_secs, unarchive, ArchivedValue};
use anyhow::{anyhow, bail, Result};
use std::collections::BTreeMap;

/// Wire `MSMMessagePacket.type` enum values:
/// - `0`: one-way notification
/// - `1`: request expecting a response
/// - `2`: response to a previous request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Send = 0,
    Request = 1,
    Response = 2,
}

impl MessageType {
    pub fn from_i64(v: i64) -> Result<Self> {
        match v {
            0 => Ok(MessageType::Send),
            1 => Ok(MessageType::Request),
            2 => Ok(MessageType::Response),
            _ => bail!("unknown MSMMessagePacket type: {v}"),
        }
    }
}

/// Wire representation of `MSMMessagePacket`.
#[derive(Debug, Clone, PartialEq)]
pub struct MessagePacket {
    pub date_create: f64,
    pub date_end_wait: f64,
    pub msg_type: MessageType,
    pub subtype: i64,
    pub name_method: String,
    pub param: ArchivedValue,
    pub result: ArchivedValue,
}

impl MessagePacket {
    pub fn new_send(method: impl Into<String>, param: ArchivedValue) -> Self {
        let now = now_apple_secs();
        Self {
            date_create: now,
            date_end_wait: now,
            msg_type: MessageType::Send,
            subtype: 0,
            name_method: method.into(),
            param,
            result: ArchivedValue::Null,
        }
    }

    pub fn new_request(method: impl Into<String>, param: ArchivedValue, timeout_secs: f64) -> Self {
        let now = now_apple_secs();
        Self {
            date_create: now,
            date_end_wait: now + timeout_secs,
            msg_type: MessageType::Request,
            subtype: 0,
            name_method: method.into(),
            param,
            result: ArchivedValue::Null,
        }
    }

    pub fn into_response(&self, result: ArchivedValue) -> Self {
        Self {
            date_create: self.date_create,
            date_end_wait: self.date_end_wait,
            msg_type: MessageType::Response,
            subtype: self.subtype,
            name_method: self.name_method.clone(),
            param: self.param.clone(),
            result,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = BTreeMap::new();
        fields.insert(
            "dateCreatePacket".to_string(),
            ArchivedValue::Date(self.date_create),
        );
        fields.insert(
            "dateEndWaitRequest".to_string(),
            ArchivedValue::Date(self.date_end_wait),
        );
        fields.insert("type".to_string(), ArchivedValue::Int(self.msg_type as i64));
        fields.insert("subtype".to_string(), ArchivedValue::Int(self.subtype));
        fields.insert(
            "nameMethod".to_string(),
            ArchivedValue::String(self.name_method.clone()),
        );
        fields.insert("paramObject".to_string(), self.param.clone());
        fields.insert("resultObject".to_string(), self.result.clone());

        let obj = ArchivedValue::Object {
            class_name: "MSMMessagePacket".to_string(),
            classes: vec!["MSMMessagePacket".to_string(), "NSObject".to_string()],
            fields,
        };
        archive(&obj)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let val = unarchive(bytes)?;
        match val {
            ArchivedValue::Object {
                class_name, fields, ..
            } if class_name == "MSMMessagePacket" => {
                let date_create = match fields.get("dateCreatePacket") {
                    Some(ArchivedValue::Date(t)) => *t,
                    _ => now_apple_secs(),
                };
                let date_end_wait = match fields.get("dateEndWaitRequest") {
                    Some(ArchivedValue::Date(t)) => *t,
                    _ => date_create,
                };
                let msg_type = MessageType::from_i64(
                    fields
                        .get("type")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0),
                )?;
                let subtype = fields
                    .get("subtype")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let name_method = fields
                    .get("nameMethod")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("MSMMessagePacket missing nameMethod"))?
                    .to_string();
                let param = fields
                    .get("paramObject")
                    .cloned()
                    .unwrap_or(ArchivedValue::Null);
                let result = fields
                    .get("resultObject")
                    .cloned()
                    .unwrap_or(ArchivedValue::Null);
                Ok(Self {
                    date_create,
                    date_end_wait,
                    msg_type,
                    subtype,
                    name_method,
                    param,
                    result,
                })
            }
            other => bail!("expected MSMMessagePacket, got {other:?}"),
        }
    }
}

/// Parsed client handshake info (`MSMClientInfo`).
#[derive(Debug, Clone)]
pub struct ClientHandshake {
    pub uid: String,
    pub name: String,
    pub model: String,
    pub system_name: String,
    pub system_version: String,
    pub client_version: String,
    pub data_protocol_version: u32,
    pub orientation: i32,
    pub screen_width: u32,
    pub screen_height: u32,
    pub udp_port: u16,
    pub supports_telemetry_cursor: bool,
    pub supports_mirror_mode: bool,
    pub supports_shared_main_mode: bool,
    pub max_compression: Option<u32>,
    pub preferred_compression: Option<u32>,
    pub preferred_fps: Option<u32>,
}

impl ClientHandshake {
    pub fn from_archived(val: &ArchivedValue) -> Result<Self> {
        let dict = val
            .as_dict()
            .ok_or_else(|| anyhow!("Handshake paramObject is not an NSDictionary"))?;

        let get_str = |k: &str, default: &str| {
            dict.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or(default)
                .to_string()
        };
        let get_u32 = |k: &str, default: u32| {
            dict.get(k)
                .and_then(parse_archived_u32)
                .unwrap_or(default)
        };
        let get_bool = |k: &str| dict.get(k).and_then(|v| v.as_bool()).unwrap_or(false);

        let raw_proto = get_u32("clientDataProtocolVersionKey", 5);
        let data_protocol_version = if raw_proto == 0 { 5 } else { raw_proto.min(5) };

        let mut width = get_u32("screenWidth", 1024);
        let mut height = get_u32("screenHeight", 768);
        let default_orient = if width > height { 1 } else { 0 };
        let orientation = dict
            .get("clientOrientationKey")
            .and_then(parse_archived_i32)
            .unwrap_or(default_orient);
        // Align to even pixels for H.264 encoder compatibility and clamp hostile huge dimensions.
        if width < 320 || height < 240 {
            width = 1024;
            height = 768;
        }
        width = width.min(8192) & !1;
        height = height.min(8192) & !1;

        let raw_model = get_str("model", "iPad");
        let trimmed_model = raw_model.trim();
        // iDisplay iOS v6.2.0 transmits the literal key-name placeholder `"model"` in MSMClientInfo.
        let model = if trimmed_model.is_empty()
            || trimmed_model.eq_ignore_ascii_case("model")
            || trimmed_model.eq_ignore_ascii_case("unknown")
        {
            if width.max(height) >= 1024 {
                "iPad".to_string()
            } else {
                "iOS Device".to_string()
            }
        } else {
            trimmed_model.to_string()
        };

        Ok(Self {
            uid: get_str("uniqueIdentifier", "unknown-ipad"),
            name: get_str("name", "iPad"),
            model,
            system_name: get_str("systemName", "iPhone OS"),
            system_version: get_str("systemVersion", "12.0"),
            client_version: get_str("clientVersion", "3.0"),
            data_protocol_version,
            orientation,
            screen_width: width,
            screen_height: height,
            udp_port: get_u32("udpPort", 0) as u16,
            supports_telemetry_cursor: get_bool("MSMClientTelemetryCursorSupportedKey"),
            supports_mirror_mode: get_bool("MSMClientMirrorModeSupportedKey"),
            supports_shared_main_mode: get_bool("MSMClientSharedMainDisplayModeSupportedKey"),
            max_compression: dict
                .get("MSMClientNumberMaxMethodCompressionKey")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            preferred_compression: dict
                .get("MSMClientNumberPreferableCompressionKey")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            preferred_fps: dict
                .get("MSMClientAmountFramePerSecondKey")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
        })
    }

    /// Whether the client's current orientation is landscape.
    /// - Legacy wire orientation: `0` = Portrait (`w <= h`), `1` = Landscape (`w > h`)
    /// - Also handles iOS `UIInterfaceOrientation`: `2` = PortraitUpsideDown, `3`/`4` = Landscape.
    pub fn is_landscape(&self) -> bool {
        matches!(self.orientation, 1 | 3 | 4)
    }

    /// Apply the client's current orientation (portrait vs landscape) to any `(width, height)` pair.
    /// Ensures portrait always produces `(min, max)` and landscape always produces `(max, min)`.
    pub fn orient_dimensions(&self, width: u32, height: u32) -> (u32, u32) {
        let short = width.min(height);
        let long = width.max(height);
        let (rw, rh) = if self.is_landscape() {
            (long, short)
        } else {
            (short, long)
        };
        ((rw & !1).max(320), (rh & !1).max(240))
    }

    /// Compute effective display resolution based on the client's screen size and current orientation.
    pub fn effective_resolution(&self) -> (u32, u32) {
        self.orient_dimensions(self.screen_width, self.screen_height)
    }
}

/// Parse an orientation integer from an `ArchivedValue` (supports `NSNumber` int/uint/float and `NSString`).
pub fn parse_archived_i32(v: &ArchivedValue) -> Option<i32> {
    match v {
        ArchivedValue::Int(i) => Some(*i as i32),
        ArchivedValue::Uint(u) => Some(*u as i32),
        ArchivedValue::Real(f) => Some(*f as i32),
        ArchivedValue::String(s) => s.trim().parse::<i32>().ok(),
        _ => None,
    }
}

/// Parse a numeric pixel dimension from an `ArchivedValue` (`NSNumber` or `NSString`).
pub fn parse_archived_u32(v: &ArchivedValue) -> Option<u32> {
    match v {
        ArchivedValue::Int(i) if *i > 0 => Some(*i as u32),
        ArchivedValue::Uint(u) if *u > 0 => Some(*u as u32),
        ArchivedValue::Real(f) if *f > 0.0 => Some(*f as u32),
        ArchivedValue::String(s) => s.trim().parse::<f64>().ok().filter(|f| *f > 0.0).map(|f| f as u32),
        _ => None,
    }
}

/// Build `AccessConfirmed` telemetry message containing host metadata.
pub fn build_access_confirmed_packet(
    user_name: &str,
    host_name: &str,
    os_version: &str,
    physical_memory: u64,
    cpu_count: u64,
    type_capture: i64,
    data_protocol_version: u32,
) -> MessagePacket {
    let mut server_info = BTreeMap::new();
    server_info.insert(
        "userName".to_string(),
        ArchivedValue::String(user_name.to_string()),
    );
    server_info.insert(
        "hostName".to_string(),
        ArchivedValue::String(host_name.to_string()),
    );
    // NSMACHOperatingSystem = 5
    server_info.insert("operationSystem".to_string(), ArchivedValue::Int(5));
    server_info.insert(
        "operationSystemName".to_string(),
        ArchivedValue::String("NSMACHOperatingSystem".to_string()),
    );
    server_info.insert(
        "operationSystemVersion".to_string(),
        ArchivedValue::String(os_version.to_string()),
    );
    server_info.insert(
        "physicalMemory".to_string(),
        ArchivedValue::Int(physical_memory as i64),
    );
    server_info.insert(
        "processorCount".to_string(),
        ArchivedValue::Uint(cpu_count),
    );
    server_info.insert(
        "activeProcessorCount".to_string(),
        ArchivedValue::Uint(cpu_count),
    );
    server_info.insert(
        "serverVersion".to_string(),
        ArchivedValue::String("3.3.0.18".to_string()),
    );
    server_info.insert(
        "hostDataProtocolVersionKey".to_string(),
        ArchivedValue::String(data_protocol_version.to_string()),
    );
    server_info.insert(
        "MSMHostTypeCaptureKey".to_string(),
        ArchivedValue::Int(type_capture),
    );
    server_info.insert(
        "MSMHostBuildKey".to_string(),
        ArchivedValue::String("FULL".to_string()),
    );
    server_info.insert(
        "MSMHostWheelXYEventSupportedKey".to_string(),
        ArchivedValue::Bool(true),
    );
    server_info.insert(
        "MSMHostSwapBytesForMELZ4Key".to_string(),
        ArchivedValue::Bool(false),
    );

    let mut payload = BTreeMap::new();
    payload.insert("isAccess".to_string(), ArchivedValue::Bool(true));
    payload.insert("serverInfo".to_string(), ArchivedValue::Dict(server_info));
    payload.insert("reason".to_string(), ArchivedValue::Int(0));

    MessagePacket::new_send("AccessConfirmed", ArchivedValue::Dict(payload))
}

/// Build declined `AccessConfirmed` telemetry message (reason 4 = denied by security/user).
pub fn build_access_declined_packet(reason: i64) -> MessagePacket {
    let mut payload = BTreeMap::new();
    payload.insert("isAccess".to_string(), ArchivedValue::Bool(false));
    payload.insert("serverInfo".to_string(), ArchivedValue::Dict(BTreeMap::new()));
    payload.insert("reason".to_string(), ArchivedValue::Int(reason));

    MessagePacket::new_send("AccessConfirmed", ArchivedValue::Dict(payload))
}

/// Build `VideoServiceAccessibleOnPort` telemetry message.
pub fn build_video_port_packet(data_port: u16) -> MessagePacket {
    MessagePacket::new_send(
        "VideoServiceAccessibleOnPort",
        ArchivedValue::Uint(data_port as u64),
    )
}

/// Build `ChangeCursorVisible` telemetry message.
pub fn build_cursor_visible_packet(visible: bool) -> MessagePacket {
    MessagePacket::new_send("ChangeCursorVisible", ArchivedValue::Bool(visible))
}

/// Build `ChangeCursorPosition` telemetry message (`{ "x": u32, "y": u32 }`).
pub fn build_cursor_position_packet(x: u32, y: u32) -> MessagePacket {
    let mut d = BTreeMap::new();
    d.insert("x".to_string(), ArchivedValue::Uint(x as u64));
    d.insert("y".to_string(), ArchivedValue::Uint(y as u64));
    MessagePacket::new_send("ChangeCursorPosition", ArchivedValue::Dict(d))
}

/// Build `ChangeCursorImage` telemetry message (PNG bytes as NSData).
pub fn build_cursor_image_packet(png_bytes: Vec<u8>) -> MessagePacket {
    MessagePacket::new_send("ChangeCursorImage", ArchivedValue::Data(png_bytes))
}

/// Build the 9-byte UDP cursor position/visibility packet:
/// `[u16_le len=9][u8 ver=1][u8 type=1][u16_le x][u16_le y][u8 hidden (0=visible, 1=hidden)]`.
pub fn build_udp_cursor_position_packet(x: u32, y: u32, visible: bool) -> [u8; 9] {
    let mut pkt = [0u8; 9];
    pkt[0..2].copy_from_slice(&9u16.to_le_bytes());
    pkt[2] = 1;
    pkt[3] = 1;
    pkt[4..6].copy_from_slice(&(x.min(u16::MAX as u32) as u16).to_le_bytes());
    pkt[6..8].copy_from_slice(&(y.min(u16::MAX as u32) as u16).to_le_bytes());
    pkt[8] = if visible { 0 } else { 1 };
    pkt
}

/// Keyboard modifier bitmask for `InputEvent::KeyModified`.
pub const KEY_MOD_SHIFT: u8 = 1 << 0;
pub const KEY_MOD_CTRL: u8 = 1 << 1;
pub const KEY_MOD_ALT: u8 = 1 << 2;
pub const KEY_MOD_META: u8 = 1 << 3;

/// Decoded input events arriving from a connected legacy display client on the Data channel.
#[derive(Debug, Clone, PartialEq)]
pub enum InputEvent {
    MouseDown {
        x: f64,
        y: f64,
        right_click: bool,
        tap_count: u8,
    },
    MouseDragged { x: f64, y: f64 },
    MouseUp { x: f64, y: f64, double_click: bool },
    /// Special non-printable key using macOS virtual key code convention:
    /// 0x33=Backspace, 0x24=Return, 0x30=Tab, 0x35=Escape, 0x75=ForwardDelete,
    /// 0x7E=Up, 0x7D=Down, 0x7B=Left, 0x7C=Right, 0x73=Home, 0x77=End, 0x74=PageUp, 0x79=PageDown.
    KeySpecial { key_code: u16 },
    KeyUnicode { ch: u16 },
    /// Multi-character text input (iOS QuickType suggestions, CJK phrases, surrogate-pair emoji).
    KeyText { text: String },
    /// Key press combined with hardware keyboard modifiers (`KEY_MOD_*` bitmask).
    KeyModified {
        key_code: Option<u16>,
        ch: Option<u16>,
        modifiers: u8,
    },
    Scroll { dx: f64, dy: f64 },
}

pub fn decode_input_event(bytes: &[u8]) -> Result<Option<InputEvent>> {
    let val = unarchive(bytes)?;
    Ok(decode_input_value(&val))
}

/// Inspect the top-level ObjC class name and field keys of a `bplist` payload for diagnostics.
pub fn describe_archived_bplist(bytes: &[u8]) -> Option<String> {
    let val = unarchive(bytes).ok()?;
    match val {
        ArchivedValue::Object {
            class_name,
            classes,
            fields,
        } => {
            let keys: Vec<&str> = fields.keys().map(String::as_str).collect();
            Some(format!(
                "class={class_name} classes={classes:?} keys={keys:?}"
            ))
        }
        other => Some(format!("non-object={other:?}")),
    }
}

fn parse_cgpoint_str(s: &str) -> Option<(f64, f64)> {
    let trimmed = s.trim().trim_start_matches('{').trim_end_matches('}');
    let (xs, ys) = trimmed.split_once(',')?;
    let x = xs.trim().parse::<f64>().ok()?;
    let y = ys.trim().parse::<f64>().ok()?;
    if x.is_finite() && y.is_finite() {
        Some((x, y))
    } else {
        None
    }
}

pub fn decode_input_value(val: &ArchivedValue) -> Option<InputEvent> {
    decode_input_value_inner(val, true)
}

fn decode_input_value_inner(val: &ArchivedValue, allow_unwrap: bool) -> Option<InputEvent> {
    let ArchivedValue::Object {
        class_name,
        classes,
        fields,
    } = val
    else {
        return None;
    };
    let is_cls = |name: &str| class_name == name || classes.iter().any(|c| c == name);

    // Compatibility: unwrap `MSMMessagePacket` at most ONE level if a client wraps an input event
    // inside `paramObject` (caps recursive `ArchivedValue::Data` unarchiving to prevent stack-overflow DoS).
    if is_cls("MSMMessagePacket") {
        if !allow_unwrap {
            return None;
        }
        if let Some(param) = fields.get("paramObject") {
            if let Some(ev) = decode_input_value_inner(param, false) {
                return Some(ev);
            }
            if let ArchivedValue::Data(raw) = param {
                if let Ok(inner) = unarchive(raw) {
                    if let Some(ev) = decode_input_value_inner(&inner, false) {
                        return Some(ev);
                    }
                }
            }
        }
        return None;
    }

    if is_cls("MSMTouchEvent") {
        let subtype = fields
            .get("_subtype")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let touches = match fields.get("_allTouches") {
            Some(ArchivedValue::Set(v)) | Some(ArchivedValue::Array(v)) => v,
            _ => return None,
        };
        let Some(ArchivedValue::Object {
            fields: t_fields, ..
        }) = touches.first()
        else {
            return None;
        };
        let phase = t_fields
            .get("_phase")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);
        let tap_count = t_fields
            .get("_tapCount")
            .and_then(|v| v.as_i64())
            .unwrap_or(1);
        let fallback_pt = t_fields
            .get("_location")
            .or_else(|| t_fields.get("location"))
            .and_then(|v| v.as_str())
            .and_then(parse_cgpoint_str);
        let x = t_fields
            .get("_location.x")
            .and_then(|v| v.as_f64())
            .or_else(|| fallback_pt.map(|p| p.0))
            .unwrap_or(0.0);
        let y = t_fields
            .get("_location.y")
            .and_then(|v| v.as_f64())
            .or_else(|| fallback_pt.map(|p| p.1))
            .unwrap_or(0.0);
        if !x.is_finite() || !y.is_finite() {
            return None;
        }

        // Touch phase mapping:
        // phase 0 = UITouchPhaseBegan (subtype != 0 => right click 0x3e9, else left mouse down 1)
        // phase 1 = UITouchPhaseMoved (left mouse dragged 6)
        // phase 3 = UITouchPhaseEnded (tapCount == 2 => double click 0x3e8, else left mouse up 2)
        // phase 4 = UITouchPhaseCancelled (e.g. app switch / incoming notification during drag ->
        //           release left mouse button so the host cursor never gets stuck pressed)
        return match phase {
            0 => Some(InputEvent::MouseDown {
                x,
                y,
                right_click: subtype != 0,
                tap_count: tap_count.clamp(1, 3) as u8,
            }),
            1 => Some(InputEvent::MouseDragged { x, y }),
            3 => Some(InputEvent::MouseUp {
                x,
                y,
                double_click: tap_count >= 2,
            }),
            4 => Some(InputEvent::MouseUp {
                x,
                y,
                double_click: false,
            }),
            _ => None,
        };
    }

    if is_cls("MSMKeyboardEvent") {
        let special = fields
            .get("specialValue")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let raw_mods = fields
            .get("modifiers")
            .or_else(|| fields.get("modifierFlags"))
            .or_else(|| fields.get("flags"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as u64;
        // Decode Apple `UIKeyModifierFlags` / `NSEventModifierFlags` (bits 17..=20).
        let mut modifiers = 0u8;
        if (raw_mods & (1 << 17)) != 0 {
            modifiers |= KEY_MOD_SHIFT;
        }
        if (raw_mods & (1 << 18)) != 0 {
            modifiers |= KEY_MOD_CTRL;
        }
        if (raw_mods & (1 << 19)) != 0 {
            modifiers |= KEY_MOD_ALT;
        }
        if (raw_mods & (1 << 20)) != 0 {
            modifiers |= KEY_MOD_META;
        }

        let special_code = match special {
            1 => Some(0x33u16), // Backspace
            2 => Some(0x24),    // Return
            3 => Some(0x30),    // Tab
            4 => Some(0x35),    // Escape
            5 => Some(0x75),    // Forward Delete
            _ => None,
        };
        if let Some(key_code) = special_code {
            return if modifiers != 0 {
                Some(InputEvent::KeyModified {
                    key_code: Some(key_code),
                    ch: None,
                    modifiers,
                })
            } else {
                Some(InputEvent::KeySpecial { key_code })
            };
        }

        // Preserve multi-char QuickType / CJK / surrogate-pair emoji strings (capped at 64 UTF-16 units).
        if let Some(ArchivedValue::String(s)) = fields.get("value") {
            let utf16_len = s.encode_utf16().count();
            if utf16_len > 1 {
                let bounded: String = s.chars().take(64).collect();
                if !bounded.is_empty() {
                    return Some(InputEvent::KeyText { text: bounded });
                }
            }
        }

        let value = fields
            .get("value")
            .and_then(|v| match v {
                // String values like "0".."9" MUST decode as UTF-16 characters ('0'=0x30..'9'=0x39),
                // never via `as_i64()` which would turn "0" into 0 (dropped), "8" into BS, "9" into TAB!
                ArchivedValue::String(s) => s.encode_utf16().next().map(|u| u as i64),
                other => other.as_i64(),
            })
            .unwrap_or(0) as u16;

        let mapped_special = match value {
            0x08 => Some(0x33u16), // BS
            0x09 => Some(0x30),    // TAB
            0x0A | 0x0D => Some(0x24), // LF/CR
            0x1B => Some(0x35),    // ESC
            0x7F | 0xF728 => Some(0x75), // DEL / NSDeleteFunctionKey
            0xF700 => Some(0x7E),  // NSUpArrowFunctionKey
            0xF701 => Some(0x7D),  // NSDownArrowFunctionKey
            0xF702 => Some(0x7B),  // NSLeftArrowFunctionKey
            0xF703 => Some(0x7C),  // NSRightArrowFunctionKey
            0xF729 => Some(0x73),  // NSHomeFunctionKey
            0xF72B => Some(0x77),  // NSEndFunctionKey
            0xF72C => Some(0x74),  // NSPageUpFunctionKey
            0xF72D => Some(0x79),  // NSPageDownFunctionKey
            _ => None,
        };
        if let Some(key_code) = mapped_special {
            return if modifiers != 0 {
                Some(InputEvent::KeyModified {
                    key_code: Some(key_code),
                    ch: None,
                    modifiers,
                })
            } else {
                Some(InputEvent::KeySpecial { key_code })
            };
        }
        if value == 0 {
            return None;
        }
        // Printable chars with only Shift already carry uppercase/shifted glyphs; use KeyModified
        // only when Cmd/Ctrl/Alt shortcut modifiers are active.
        let shortcut_mods = modifiers & (KEY_MOD_CTRL | KEY_MOD_ALT | KEY_MOD_META);
        return if shortcut_mods != 0 {
            Some(InputEvent::KeyModified {
                key_code: None,
                ch: Some(value),
                modifiers,
            })
        } else {
            Some(InputEvent::KeyUnicode { ch: value })
        };
    }

    if is_cls("MSMWheelXYEvent") {
        let dx = fields
            .get("valueX")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let dy = fields
            .get("valueY")
            .and_then(|v| v.as_f64())
            .or_else(|| fields.get("value").and_then(|v| v.as_f64()))
            .unwrap_or(0.0);
        if !dx.is_finite() || !dy.is_finite() {
            return None;
        }
        return Some(InputEvent::Scroll {
            dx: dx.clamp(-1000.0, 1000.0),
            dy: dy.clamp(-1000.0, 1000.0),
        });
    }

    if is_cls("MSMWheelEvent") {
        let dy = fields
            .get("value")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if !dy.is_finite() {
            return None;
        }
        return Some(InputEvent::Scroll {
            dx: 0.0,
            dy: dy.clamp(-1000.0, 1000.0),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_and_access_confirmed_roundtrip() {
        let mut hdict = BTreeMap::new();
        hdict.insert(
            "uniqueIdentifier".to_string(),
            ArchivedValue::String("ipad-air-1".to_string()),
        );
        hdict.insert(
            "name".to_string(),
            ArchivedValue::String("iPad Air".to_string()),
        );
        hdict.insert(
            "model".to_string(),
            ArchivedValue::String("iPad".to_string()),
        );
        hdict.insert("screenWidth".to_string(), ArchivedValue::Int(1024));
        hdict.insert("screenHeight".to_string(), ArchivedValue::Int(768));
        hdict.insert(
            "clientDataProtocolVersionKey".to_string(),
            ArchivedValue::String("5".to_string()),
        );
        hdict.insert(
            "MSMClientTelemetryCursorSupportedKey".to_string(),
            ArchivedValue::Bool(true),
        );

        let pkt = MessagePacket::new_send("Handshake", ArchivedValue::Dict(hdict));
        let wire = pkt.encode().unwrap();
        let dec = MessagePacket::decode(&wire).unwrap();
        assert_eq!(dec.name_method, "Handshake");
        let hs = ClientHandshake::from_archived(&dec.param).unwrap();
        assert_eq!(hs.uid, "ipad-air-1");
        assert_eq!(hs.screen_width, 1024);
        assert_eq!(hs.screen_height, 768);
        assert_eq!(hs.data_protocol_version, 5);
        assert!(hs.supports_telemetry_cursor);

        let ac = build_access_confirmed_packet("user", "MacM1", "Version 15.0", 16 << 30, 8, 3, 5);
        let ac_wire = ac.encode().unwrap();
        let ac_dec = MessagePacket::decode(&ac_wire).unwrap();
        assert_eq!(ac_dec.name_method, "AccessConfirmed");
        let ac_dict = ac_dec.param.as_dict().unwrap();
        assert_eq!(ac_dict.get("isAccess").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn touch_and_keyboard_decode() {
        let mut touch_fields = BTreeMap::new();
        touch_fields.insert("_phase".to_string(), ArchivedValue::Int(0));
        touch_fields.insert("_tapCount".to_string(), ArchivedValue::Int(1));
        touch_fields.insert("_location.x".to_string(), ArchivedValue::Real(320.5));
        touch_fields.insert("_location.y".to_string(), ArchivedValue::Real(240.25));
        let touch = ArchivedValue::Object {
            class_name: "MSMTouch".to_string(),
            classes: vec!["MSMTouch".to_string(), "NSObject".to_string()],
            fields: touch_fields,
        };
        let mut ev_fields = BTreeMap::new();
        ev_fields.insert("_subtype".to_string(), ArchivedValue::Int(0));
        ev_fields.insert("_allTouches".to_string(), ArchivedValue::Set(vec![touch]));
        let ev = ArchivedValue::Object {
            class_name: "MSMTouchEvent".to_string(),
            classes: vec![
                "MSMTouchEvent".to_string(),
                "MSMEvent".to_string(),
                "NSObject".to_string(),
            ],
            fields: ev_fields,
        };
        let bytes = archive(&ev).unwrap();
        assert_eq!(
            decode_input_event(&bytes).unwrap(),
            Some(InputEvent::MouseDown {
                x: 320.5,
                y: 240.25,
                right_click: false,
                tap_count: 1,
            })
        );

        // UITouchPhaseCancelled (4) must release the mouse button cleanly
        let mut cancel_touch = BTreeMap::new();
        cancel_touch.insert("_phase".to_string(), ArchivedValue::Int(4));
        cancel_touch.insert("_tapCount".to_string(), ArchivedValue::Int(1));
        cancel_touch.insert("_location.x".to_string(), ArchivedValue::Real(100.0));
        cancel_touch.insert("_location.y".to_string(), ArchivedValue::Real(200.0));
        let mut cancel_fields = BTreeMap::new();
        cancel_fields.insert("_subtype".to_string(), ArchivedValue::Int(0));
        cancel_fields.insert(
            "_allTouches".to_string(),
            ArchivedValue::Set(vec![ArchivedValue::Object {
                class_name: "MSMTouch".to_string(),
                classes: vec!["MSMTouch".to_string(), "NSObject".to_string()],
                fields: cancel_touch,
            }]),
        );
        let cancel_bytes = archive(&ArchivedValue::Object {
            class_name: "MSMTouchEvent".to_string(),
            classes: vec!["MSMTouchEvent".to_string(), "NSObject".to_string()],
            fields: cancel_fields,
        })
        .unwrap();
        assert_eq!(
            decode_input_event(&cancel_bytes).unwrap(),
            Some(InputEvent::MouseUp {
                x: 100.0,
                y: 200.0,
                double_click: false
            })
        );

        // Keyboard Tab & Escape control chars map to KeySpecial
        let mut kb = BTreeMap::new();
        kb.insert("specialValue".to_string(), ArchivedValue::Int(0));
        kb.insert("value".to_string(), ArchivedValue::Int(0x1B));
        let kb_bytes = archive(&ArchivedValue::Object {
            class_name: "MSMKeyboardEvent".to_string(),
            classes: vec!["MSMKeyboardEvent".to_string(), "NSObject".to_string()],
            fields: kb,
        })
        .unwrap();
        assert_eq!(
            decode_input_event(&kb_bytes).unwrap(),
            Some(InputEvent::KeySpecial { key_code: 0x35 })
        );

        // String-valued keyboard value falls back to UTF-16 code unit
        let mut kb_str = BTreeMap::new();
        kb_str.insert("specialValue".to_string(), ArchivedValue::Int(0));
        kb_str.insert("value".to_string(), ArchivedValue::String("A".to_string()));
        let kb_str_bytes = archive(&ArchivedValue::Object {
            class_name: "MSMKeyboardEvent".to_string(),
            classes: vec!["MSMKeyboardEvent".to_string(), "NSObject".to_string()],
            fields: kb_str,
        })
        .unwrap();
        assert_eq!(
            decode_input_event(&kb_str_bytes).unwrap(),
            Some(InputEvent::KeyUnicode { ch: b'A' as u16 })
        );

        // BUG-A1 regression: string digits "0".."9" MUST decode to ASCII '0'..'9' (0x30..0x39),
        // never 0 (dropped), control chars 1..7, 0x08 (Backspace), or 0x09 (Tab)!
        for digit in '0'..='9' {
            let mut d = BTreeMap::new();
            d.insert("specialValue".to_string(), ArchivedValue::Int(0));
            d.insert("value".to_string(), ArchivedValue::String(digit.to_string()));
            let bytes = archive(&ArchivedValue::Object {
                class_name: "MSMKeyboardEvent".to_string(),
                classes: vec!["MSMKeyboardEvent".to_string(), "NSObject".to_string()],
                fields: d,
            })
            .unwrap();
            assert_eq!(
                decode_input_event(&bytes).unwrap(),
                Some(InputEvent::KeyUnicode { ch: digit as u16 }),
                "string digit {digit:?} must decode as Unicode character, not numeric control code"
            );
        }

        // BUG-A5 regression: non-finite (NaN / Inf) touch & wheel coordinates must be rejected
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut tf = BTreeMap::new();
            tf.insert("_phase".to_string(), ArchivedValue::Int(0));
            tf.insert("_location.x".to_string(), ArchivedValue::Real(bad));
            tf.insert("_location.y".to_string(), ArchivedValue::Real(100.0));
            let touch_obj = ArchivedValue::Object {
                class_name: "MSMTouch".to_string(),
                classes: vec!["MSMTouch".to_string(), "NSObject".to_string()],
                fields: tf,
            };
            let mut t = BTreeMap::new();
            t.insert("_allTouches".to_string(), ArchivedValue::Array(vec![touch_obj]));
            let tb = archive(&ArchivedValue::Object {
                class_name: "MSMTouchEvent".to_string(),
                classes: vec!["MSMTouchEvent".to_string(), "NSObject".to_string()],
                fields: t,
            })
            .unwrap();
            assert_eq!(decode_input_event(&tb).unwrap(), None);

            let mut w = BTreeMap::new();
            w.insert("valueX".to_string(), ArchivedValue::Real(1.0));
            w.insert("valueY".to_string(), ArchivedValue::Real(bad));
            let wb = archive(&ArchivedValue::Object {
                class_name: "MSMWheelXYEvent".to_string(),
                classes: vec!["MSMWheelXYEvent".to_string(), "NSObject".to_string()],
                fields: w,
            })
            .unwrap();
            assert_eq!(decode_input_event(&wb).unwrap(), None);
        }

        // Wheel clamping & right-click / CGPoint string decoding
        let mut wh = BTreeMap::new();
        wh.insert("valueX".to_string(), ArchivedValue::Real(99999.0));
        wh.insert("valueY".to_string(), ArchivedValue::Real(-99999.0));
        let wh_bytes = archive(&ArchivedValue::Object {
            class_name: "MSMWheelXYEvent".to_string(),
            classes: vec!["MSMWheelXYEvent".to_string(), "NSObject".to_string()],
            fields: wh,
        })
        .unwrap();
        assert_eq!(
            decode_input_event(&wh_bytes).unwrap(),
            Some(InputEvent::Scroll {
                dx: 1000.0,
                dy: -1000.0
            })
        );

        let mut rtf = BTreeMap::new();
        rtf.insert("_phase".to_string(), ArchivedValue::Int(0));
        rtf.insert("_location".to_string(), ArchivedValue::String("{321.5, 456.25}".to_string()));
        let rt_touch = ArchivedValue::Object {
            class_name: "MSMTouch".to_string(),
            classes: vec!["MSMTouch".to_string(), "NSObject".to_string()],
            fields: rtf,
        };
        let mut rt = BTreeMap::new();
        rt.insert("_subtype".to_string(), ArchivedValue::Int(1));
        rt.insert("_allTouches".to_string(), ArchivedValue::Array(vec![rt_touch]));
        let rt_bytes = archive(&ArchivedValue::Object {
            class_name: "MSMTouchEvent".to_string(),
            classes: vec!["MSMTouchEvent".to_string(), "NSObject".to_string()],
            fields: rt,
        })
        .unwrap();
        assert_eq!(
            decode_input_event(&rt_bytes).unwrap(),
            Some(InputEvent::MouseDown {
                x: 321.5,
                y: 456.25,
                right_click: true,
                tap_count: 1
            })
        );

        // BUG-A7 regression: hostile huge handshake dimensions are clamped to <= 8192 even pixels
        let mut hs_dict = BTreeMap::new();
        hs_dict.insert("screenWidth".to_string(), ArchivedValue::Int(99999));
        hs_dict.insert("screenHeight".to_string(), ArchivedValue::Int(50001));
        let hs = ClientHandshake::from_archived(&ArchivedValue::Dict(hs_dict)).unwrap();
        assert_eq!(hs.screen_width, 8192);
        assert_eq!(hs.screen_height, 8192);
    }

    #[test]
    fn udp_cursor_packet_matches_legacy_layout() {
        let vis = build_udp_cursor_position_packet(512, 384, true);
        assert_eq!(vis, [9, 0, 1, 1, 0, 2, 128, 1, 0]);
        let hid = build_udp_cursor_position_packet(10, 20, false);
        assert_eq!(hid, [9, 0, 1, 1, 10, 0, 20, 0, 1]);
    }

    #[test]
    fn nested_msm_message_packet_data_unwrapping_is_capped_at_depth_one() {
        // Build a valid inner keyboard event
        let mut kf = BTreeMap::new();
        kf.insert("value".to_string(), ArchivedValue::String("a".to_string()));
        let key_obj = ArchivedValue::Object {
            class_name: "MSMKeyboardEvent".to_string(),
            classes: vec!["MSMKeyboardEvent".to_string(), "NSObject".to_string()],
            fields: kf,
        };
        let key_bytes = archive(&key_obj).unwrap();

        // Depth-1 wrapper: MSMMessagePacket { paramObject: Data(key_bytes) } -> MUST decode cleanly
        let wrap_once = |inner: Vec<u8>| {
            let mut f = BTreeMap::new();
            f.insert("paramObject".to_string(), ArchivedValue::Data(inner));
            archive(&ArchivedValue::Object {
                class_name: "MSMMessagePacket".to_string(),
                classes: vec!["MSMMessagePacket".to_string(), "NSObject".to_string()],
                fields: f,
            })
            .unwrap()
        };
        let depth1 = wrap_once(key_bytes);
        assert_eq!(
            decode_input_event(&depth1).unwrap(),
            Some(InputEvent::KeyUnicode { ch: b'a' as u16 })
        );

        // Depth-2+ wrapper: MSMMessagePacket { paramObject: Data(MSMMessagePacket { ... }) } ->
        // MUST stop at depth 1 (returning Ok(None)) so deep nested Data chains never overflow the stack (P2-A4)!
        let mut nested = depth1;
        for _ in 0..50 {
            nested = wrap_once(nested);
        }
        assert_eq!(
            decode_input_event(&nested).unwrap(),
            None,
            "nested MSMMessagePacket Data wrappers past depth 1 must fail fast without recursing"
        );
    }
}
