use actix_web::{get, http::header::HeaderMap, web, HttpRequest, HttpResponse, Responder};

use crate::app::State;

use crate::types::{
    ForwardedRequest, USER_AGENT, X_FORWARDED_FOR, X_FORWARDED_HOST, X_FORWARDED_METHOD,
    X_FORWARDED_PROTO, X_FORWARDED_URI,
};

#[get("/ring")]
pub async fn handler(req: HttpRequest, state: web::Data<State>) -> impl Responder {
    let headers = req.headers();

    let require_single_header = |name: &str| {
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
    };

    let addr = {
        let Some(addr) = req.peer_addr() else {
            log::error!("failed to get peer IP address");
            return HttpResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR);
        };

        let addr = addr.ip();
        if !state.trusted_proxies.is_trusted(&addr) {
            log::info!("got a request from an untrusted proxy IP: {}", addr);
            return HttpResponse::new(http::StatusCode::FORBIDDEN);
        }

        let Some(xff) = require_single_header(X_FORWARDED_FOR) else {
            return HttpResponse::BadRequest().finish();
        };

        let Some(forwarded_addr) = state.trusted_proxies.get_forwarded_ip(&xff) else {
            return HttpResponse::BadRequest().finish();
        };

        forwarded_addr
    };

    let scheme = {
        let Some(xfp) = require_single_header(X_FORWARDED_PROTO) else {
            return HttpResponse::BadRequest().finish();
        };

        let Ok(scheme) = xfp.parse() else {
            return HttpResponse::BadRequest().finish();
        };

        scheme
    };

    let Some(host) = require_single_header(X_FORWARDED_HOST) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(uri) = require_single_header(X_FORWARDED_URI) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(method) = require_single_header(X_FORWARDED_METHOD) else {
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

    let country_code = match state.geoip.country_code(&addr) {
        Ok(result) => result,
        Err(e) => {
            log::error!("failed to lookup country code: {}", e);
            return HttpResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let (asn, org) = {
        match state.geoip.net_info(&addr) {
            Ok(Some(info)) => (info.asn, info.org),
            Ok(None) => (None, None),
            Err(e) => {
                log::error!("failed to lookup ASN data: {}", e);
                return HttpResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    };

    let req = ForwardedRequest {
        addr,
        user_agent,
        host,
        method,
        uri,
        path,
        country_code,
        asn,
        org,
        scheme,
        timestamp: chrono::Utc::now(),
    };

    dbg!(&req);

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
