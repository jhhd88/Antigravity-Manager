use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use crate::proxy::server::AppState;
use crate::modules::security_db;

/// IP 黑白名单过滤中间件
pub async fn ip_filter_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // 读取安全配置
    let security_config = state.security.read().await;

    // [FIX-A] 根据部署模式选择 IP 提取策略：
    // - allow_lan_access=true 表示可能在反代后面，信任 X-Forwarded-For
    // - 否则优先使用 TCP 连接 IP，防止 header 伪造绕过
    let trust_proxy_headers = security_config.allow_lan_access;
    let client_ip = extract_client_ip(&request, trust_proxy_headers);

    if let Some(ip) = &client_ip {
        // 1. 检查白名单 (如果启用白名单模式,只允许白名单 IP)
        if security_config.security_monitor.whitelist.enabled {
            match security_db::is_ip_in_whitelist(ip) {
                Ok(true) => {
                    // 在白名单中,直接放行
                    tracing::debug!("[IP Filter] IP {} is in whitelist, allowing", ip);
                    return next.run(request).await;
                }
                Ok(false) => {
                    // 不在白名单中,且启用了白名单模式,拒绝访问
                    tracing::warn!("[IP Filter] IP {} not in whitelist, blocking", ip);
                    return create_blocked_response(
                        ip,
                        "Access denied. Your IP is not in the whitelist.",
                    );
                }
                Err(e) => {
                    // [FIX-B] 白名单模式下 DB 错误 => fail-closed (503)
                    tracing::error!("[IP Filter] Failed to check whitelist: {}, denying request (fail-closed)", e);
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Security check temporarily unavailable. Please try again later.",
                    ).into_response();
                }
            }
        } else {
            // 白名单优先模式: 如果在白名单中,跳过黑名单检查
            if security_config.security_monitor.whitelist.whitelist_priority {
                match security_db::is_ip_in_whitelist(ip) {
                    Ok(true) => {
                        tracing::debug!("[IP Filter] IP {} is in whitelist (priority mode), skipping blacklist check", ip);
                        return next.run(request).await;
                    }
                    Ok(false) => {
                        // 继续检查黑名单
                    }
                    Err(e) => {
                        tracing::error!("[IP Filter] Failed to check whitelist: {}", e);
                        // 优先模式下白名单查询失败不阻断，继续检查黑名单
                    }
                }
            }
        }

        // 2. 检查黑名单
        if security_config.security_monitor.blacklist.enabled {
            match security_db::get_blacklist_entry_for_ip(ip) {
                Ok(Some(entry)) => {
                    tracing::warn!("[IP Filter] IP {} is in blacklist, blocking", ip);
                    
                    // 构建详细的封禁消息
                    let reason = entry.reason.as_deref().unwrap_or("Malicious activity detected");
                    let ban_type = if let Some(expires_at) = entry.expires_at {
                        let now = chrono::Utc::now().timestamp();
                        let remaining_seconds = expires_at - now;
                        
                        if remaining_seconds > 0 {
                            let hours = remaining_seconds / 3600;
                            let minutes = (remaining_seconds % 3600) / 60;
                            
                            if hours > 24 {
                                let days = hours / 24;
                                format!("Temporary ban. Please try again after {} day(s).", days)
                            } else if hours > 0 {
                                format!("Temporary ban. Please try again after {} hour(s) and {} minute(s).", hours, minutes)
                            } else {
                                format!("Temporary ban. Please try again after {} minute(s).", minutes)
                            }
                        } else {
                            "Temporary ban (expired, will be removed soon).".to_string()
                        }
                    } else {
                        "Permanent ban.".to_string()
                    };
                    
                    let detailed_message = format!(
                        "Access denied. Reason: {}. {}",
                        reason,
                        ban_type
                    );
                    
                    // 记录被封禁的访问日志
                    let log = security_db::IpAccessLog {
                        id: uuid::Uuid::new_v4().to_string(),
                        client_ip: ip.clone(),
                        timestamp: chrono::Utc::now().timestamp(),
                        method: Some(request.method().to_string()),
                        path: Some(request.uri().to_string()),
                        user_agent: request
                            .headers()
                            .get("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string()),
                        status: Some(403),
                        duration: Some(0),
                        api_key_hash: None,
                        blocked: true,
                        block_reason: Some(format!("IP in blacklist: {}", reason)),
                        username: None,
                    };
                    
                    tokio::spawn(async move {
                        if let Err(e) = security_db::save_ip_access_log(&log) {
                            tracing::error!("[IP Filter] Failed to save blocked access log: {}", e);
                        }
                    });
                    
                    return create_blocked_response(
                        ip,
                        &detailed_message,
                    );
                }
                Ok(None) => {
                    // 不在黑名单中,放行
                    tracing::debug!("[IP Filter] IP {} not in blacklist, allowing", ip);
                }
                Err(e) => {
                    tracing::error!("[IP Filter] Failed to check blacklist: {}", e);
                }
            }
        }
    } else {
        tracing::warn!("[IP Filter] Unable to extract client IP from request");
    }

    // 放行请求
    next.run(request).await
}

/// 从请求中提取客户端 IP
///
/// [FIX-A] 安全 IP 提取策略：
/// - `trust_proxy_headers=false`（默认本机模式）: 优先使用 TCP 连接 IP (ConnectInfo)，
///   防止客户端伪造 X-Forwarded-For 绕过 IP 黑白名单。
/// - `trust_proxy_headers=true`（LAN/反代模式）: 优先使用代理 header，
///   因为此时 ConnectInfo 是反代 IP 而非真实客户端 IP。
fn extract_client_ip(request: &Request, trust_proxy_headers: bool) -> Option<String> {
    if trust_proxy_headers {
        // 反代模式：优先信任代理 header
        request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            .or_else(|| {
                request
                    .headers()
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .or_else(|| {
                // 回退到 TCP 连接 IP
                request
                    .extensions()
                    .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                    .map(|info| info.0.ip().to_string())
            })
    } else {
        // 本机模式：优先使用 TCP 连接 IP，不信任可伪造的 header
        request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|info| info.0.ip().to_string())
            .or_else(|| {
                // ConnectInfo 不可用时回退到 header（如测试环境）
                request
                    .headers()
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            })
            .or_else(|| {
                request
                    .headers()
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
    }
}

/// 创建被封禁的响应
fn create_blocked_response(ip: &str, message: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "ip_blocked",
            "code": "ip_blocked",
            "ip": ip,
        }
    });
    
    (
        StatusCode::FORBIDDEN,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| message.to_string()),
    )
        .into_response()
}
