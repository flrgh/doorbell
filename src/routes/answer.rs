use crate::geo::GeoIp;
use crate::net::TrustedProxies;
use crate::rules::Collection;
use crate::types::Repository;
use crate::{access, rules::Manager};
use actix_web::{get, http::header::HeaderMap, post, web, HttpRequest, HttpResponse, Responder};
use minijinja as mj;
use serde::Deserialize;
use tokio::sync::RwLock;

static TEMPLATE: &str = include_str!("../templates/answer.html");
static TEMPLATE_NAME: &str = "answer.html";

async fn update_matcher(event: &str, manager: web::Data<Manager>) {
    if let Err(e) = manager.update_matcher().await {
        log::error!("failed rebuilding matcher after rule {}: {}", event, e);
    } else {
        log::info!("rebuilt matcher after rule {}", event);
    }
}

#[inline]
fn bad_request() -> HttpResponse {
    HttpResponse::BadRequest().finish()
}

#[inline]
fn internal_error() -> HttpResponse {
    HttpResponse::InternalServerError().finish()
}

#[inline]
fn not_found() -> HttpResponse {
    HttpResponse::NotFound().finish()
}

#[derive(Deserialize)]
struct AnswerQuery {
    #[serde(alias = "t")]
    token: String,
}

#[get("/answer")]
pub async fn get(
    req: HttpRequest,
    query: web::Query<AnswerQuery>,
    tp: web::Data<TrustedProxies>,
    access_control: web::Data<access::Control>,
) -> impl Responder {
    let AnswerQuery { token } = query.into_inner();

    let forwarded = if token == "TEST" {
        access::Request::dummy()
    } else {
        let Some(forwarded) = access_control.get_by_token(&token).await else {
            return not_found();
        };

        forwarded
    };

    let is_current_ip = &tp.get_client_ip(&req) == forwarded.addr.as_ref();

    //dbg!(forwarded, is_current_ip);

    let mut env = mj::Environment::new();
    env.add_template(TEMPLATE_NAME, TEMPLATE).unwrap();
    let tpl = env.get_template(TEMPLATE_NAME).unwrap();

    let ctx = mj::context! {
        map_link => String::new(),
        search_link => String::new(),
        current_ip => is_current_ip,
        req => forwarded.request,
        token => token,
    };

    let res = tpl.render(ctx).unwrap();

    HttpResponse::Ok()
        .insert_header(("content-type", "text/html"))
        .body(res)
}

#[derive(Deserialize)]
struct AnswerForm {
    action: Action,
    subject: Subject,
    scope: Scope,
    period: Period,
    token: String,
}

#[derive(Deserialize)]
enum Action {
    Approve,
    Deny,
}

#[derive(Deserialize)]
enum Subject {
    Addr,
    UserAgent,
}

#[derive(Deserialize)]
enum Scope {
    Global,
    Host,
    Url,
}

#[derive(Deserialize)]
enum Period {
    Minute,
    Hour,
    Day,
    Week,
    Forever,
}

#[post("/answer")]
pub async fn post(
    form: web::Form<AnswerForm>,
    access_control: web::Data<access::Control>,
    manager: web::Data<crate::rules::Manager>,
    repo: web::Data<crate::rules::Repository>,
) -> impl Responder {
    let ans = form.into_inner();

    let Some(forwarded) = access_control.get_by_token(&ans.token).await else {
        return not_found();
    };

    let mut rule = crate::rules::RuleBuilder::default();

    rule.source(crate::rules::Source::User);

    rule.action(match ans.action {
        Action::Approve => crate::rules::Action::Allow,
        Action::Deny => crate::rules::Action::Deny,
    });

    match ans.scope {
        Scope::Global => {}
        Scope::Host => {
            rule.host(Some(crate::types::Pattern::Plain(
                forwarded.request.host.clone(),
            )));
        }
        Scope::Url => {
            rule.path(Some(crate::types::Pattern::Plain(
                forwarded.request.path.clone(),
            )));
        }
    };

    match ans.subject {
        Subject::Addr => {
            rule.addr(forwarded.request.addr);
        }
        Subject::UserAgent => {
            rule.user_agent(Some(crate::types::Pattern::Plain(
                forwarded.request.user_agent.clone(),
            )));
        }
    }

    let rule = match rule.build() {
        Ok(rule) => rule,
        Err(e) => {
            log::error!("failed building rule: {}", e);
            return internal_error();
        }
    };

    match repo.insert(rule.clone()).await {
        Ok(_) => {
            log::debug!("Created a new rule: {:?}", &rule);
            update_matcher("creation", manager).await;
            HttpResponse::Created()
                .insert_header(("content-type", "text/html"))
                .finish()
        }
        Err(e) => {
            dbg!(e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
