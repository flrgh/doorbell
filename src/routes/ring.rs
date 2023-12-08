use tokio::sync::RwLock;

use actix_web::{get, http::header::HeaderMap, web, HttpRequest, HttpResponse, Responder};

use crate::access;
use crate::geo::GeoIp;
use crate::net::TrustedProxies;
use crate::rules::Collection;
use crate::types::{
    ForwardedRequest, Method, Scheme, USER_AGENT, X_FORWARDED_FOR, X_FORWARDED_HOST,
    X_FORWARDED_METHOD, X_FORWARDED_PROTO, X_FORWARDED_URI,
};

#[inline]
fn bad_request() -> HttpResponse {
    HttpResponse::BadRequest().finish()
}

#[inline]
fn internal_error() -> HttpResponse {
    HttpResponse::InternalServerError().finish()
}

trait GetHeader {
    fn get_single<'a>(&'a self, name: &str) -> Option<&'a str>;
}

impl GetHeader for HeaderMap {
    fn get_single<'a>(&'a self, name: &str) -> Option<&'a str> {
        let mut iter = self.get_all(name);

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
                Ok(s) => Some(s),
                Err(e) => {
                    log::debug!("peer sent invalid {} header: {}", name, e);
                    None
                }
            },
        }
    }
}

#[get("/ring")]
pub async fn handler(
    req: HttpRequest,
    tp: web::Data<TrustedProxies>,
    geoip: web::Data<GeoIp>,
    rules: web::Data<RwLock<Collection>>,
    access_repo: web::Data<access::Repository>,
) -> impl Responder {
    let headers = req.headers();

    let addr = {
        let Some(addr) = req.peer_addr() else {
            log::error!("failed to get peer IP address");
            return internal_error();
        };

        let addr = addr.ip();
        if !tp.is_trusted(&addr) {
            log::info!("got a request from an untrusted proxy IP: {}", addr);
            return HttpResponse::new(http::StatusCode::FORBIDDEN);
        }

        let Some(xff) = headers.get_single(X_FORWARDED_FOR) else {
            return bad_request();
        };

        let Some(forwarded_addr) = tp.get_forwarded_ip(xff) else {
            return bad_request();
        };

        forwarded_addr
    };

    let scheme = {
        let Some(xfp) = headers.get_single(X_FORWARDED_PROTO) else {
            return bad_request();
        };

        let Ok(scheme) = xfp.parse::<Scheme>() else {
            return bad_request();
        };

        scheme
    };

    let Some(host) = headers.get_single(X_FORWARDED_HOST) else {
        return bad_request();
    };

    let Some(uri) = headers.get_single(X_FORWARDED_URI) else {
        return bad_request();
    };

    let method = {
        let Some(method) = headers.get_single(X_FORWARDED_METHOD) else {
            return bad_request();
        };

        let Ok(method) = method.parse::<Method>() else {
            return bad_request();
        };

        method
    };

    let user_agent = headers.get_single(USER_AGENT).unwrap_or("");

    let path = uri.split_once('?').map(|(path, _rest)| path).unwrap_or(uri);

    let country_code = match geoip.country_code(&addr) {
        Ok(result) => result,
        Err(e) => {
            log::error!("failed to lookup country code: {}", e);
            return internal_error();
        }
    };

    let (asn, org) = {
        match geoip.net_info(&addr) {
            Ok(Some(info)) => (info.asn, info.org),
            Ok(None) => (None, None),
            Err(e) => {
                log::error!("failed to lookup ASN data: {}", e);
                return internal_error();
            }
        }
    };

    let req = {
        let built = ForwardedRequest::builder()
            .addr(addr)
            .asn(asn)
            .org(org)
            .scheme(scheme)
            .host(host)
            .path(path)
            .uri(uri)
            .method(method)
            .country_code(country_code)
            .user_agent(user_agent)
            .build();

        match built {
            Ok(req) => req,
            Err(err) => {
                log::error!("failed building forwarded request: {}", err);
                return internal_error();
            }
        }
    };

    dbg!(&req);

    let status = {
        let matched = rules.read().await.get_match(&req).cloned();

        if let Some(rule) = matched {
            use crate::rules::Action;
            log::trace!("request {:?} matched rule {:?}", req, rule);

            match rule.action {
                Action::Allow => {
                    log::debug!("/ring => ALLOW");
                    http::StatusCode::OK
                }
                Action::Deny => {
                    log::debug!("/ring => DENY");
                    http::StatusCode::FORBIDDEN
                }
            }
        } else {
            log::trace!("request {:?} did not match any rule", req);
            log::debug!("/ring => UNKNOWN");
            access_repo.get_ref().incoming(&req).await;
            http::StatusCode::UNAUTHORIZED
        }
    };

    HttpResponse::new(status)
}
