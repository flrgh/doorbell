use actix_web::{get, http::header::HeaderMap, web, HttpRequest, HttpResponse, Responder};

use super::super::State;

use crate::types::{
    ForwardedRequest, USER_AGENT, X_FORWARDED_FOR, X_FORWARDED_HOST, X_FORWARDED_METHOD,
    X_FORWARDED_PROTO, X_FORWARDED_URI,
};

#[get("/ring")]
pub async fn handler(req: HttpRequest, state: web::Data<State>) -> impl Responder {
    let Some(addr) = req.peer_addr() else {
        log::error!("failed to get peer IP address");
        return HttpResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR);
    };

    let addr = addr.ip();
    if !state.trusted_proxies.is_trusted(&addr) {
        log::info!("got a request from an untrusted proxy IP: {}", addr);
        return HttpResponse::new(http::StatusCode::FORBIDDEN);
    }

    let headers = req.headers();

    fn require_single_header(name: &str, headers: &HeaderMap) -> Option<String> {
        let mut iter = headers.get_all(name);
        match (iter.next(), iter.next()) {
            (None, _) => {
                log::debug!("peer did not send a {} header", name);
                None
            }
            (Some(_), Some(_)) => {
                log::debug!("peer sent more than one {} header", name);
                None
            }
            (Some(value), None) => match value.to_str() {
                Ok(s) => Some(s.to_owned()),
                Err(e) => {
                    log::debug!("peer sent invalid {} header: {}", name, e);
                    None
                }
            },
        }
    }

    let Some(xff) = require_single_header(X_FORWARDED_FOR, headers) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(forwarded_addr) = state.trusted_proxies.get_forwarded_ip(&xff) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(scheme) = require_single_header(X_FORWARDED_PROTO, headers) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(host) = require_single_header(X_FORWARDED_HOST, headers) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(uri) = require_single_header(X_FORWARDED_URI, headers) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(method) = require_single_header(X_FORWARDED_METHOD, headers) else {
        return HttpResponse::BadRequest().finish();
    };

    let Ok(method) = method.parse() else {
        return HttpResponse::BadRequest().finish();
    };

    let user_agent = match headers.get(USER_AGENT) {
        Some(value) => match value.to_str() {
            Ok(s) => s.to_owned(),
            Err(e) => {
                log::debug!("peer sent invalid {} header: {}", USER_AGENT, e);
                return HttpResponse::BadRequest().finish();
            }
        },
        None => String::from(""),
    };

    fn get_path(uri: &str) -> String {
        uri.split_once('?').get_or_insert((uri, "")).0.to_owned()
    }

    let path = get_path(&uri);

    let req = ForwardedRequest {
        addr: forwarded_addr,
        user_agent,
        host,
        method,
        uri,
        path,
        country_code: None,
        asn: None,
        org: None,
        scheme,
        timestamp: chrono::Utc::now(),
    };

    let status = {
        let matched = match state.rules.read() {
            Ok(rules) => rules.get_match(&req).cloned(),
            Err(e) => {
                log::error!("{}", e);
                return HttpResponse::InternalServerError().finish();
            }
        };

        if let Some(rule) = matched {
            use crate::rules::{Action, DenyAction};
            log::trace!("request {:?} matched rule {:?}", req, rule);

            match rule.action {
                Action::Allow => {
                    log::debug!("/ring => ALLOW");
                    http::StatusCode::OK
                }
                Action::Deny => {
                    log::debug!("/ring => DENY");
                    if let Some(DenyAction::Tarpit) = rule.deny_action {
                        log::debug!("Tarpitting request");
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    }

                    http::StatusCode::FORBIDDEN
                }
            }
        } else {
            log::trace!("request {:?} did not match any rule", req);
            log::debug!("/ring => UNKNOWN");
            http::StatusCode::UNAUTHORIZED
        }
    };

    HttpResponse::new(status)
}
