use std::sync::Arc;

use crate::{
    CalDavPrincipalUri,
    principal::{PrincipalResource, PrincipalResourceService},
};
use rstest::rstest;
use rustical_dav::resource::{Resource, ResourceService};
use rustical_store::auth::{Principal, PrincipalType::Individual};
use rustical_store_sqlite::{
    SqliteStore,
    calendar_store::SqliteCalendarStore,
    principal_store::SqlitePrincipalStore,
    tests::{get_test_calendar_store, get_test_principal_store, get_test_subscription_store},
};
use rustical_xml::XmlSerializeRoot;

#[rstest]
#[tokio::test]
async fn test_principal_resource(
    #[from(get_test_calendar_store)]
    #[future]
    cal_store: SqliteCalendarStore,
    #[from(get_test_principal_store)]
    #[future]
    auth_provider: SqlitePrincipalStore,
    #[from(get_test_subscription_store)]
    #[future]
    sub_store: SqliteStore,
) {
    let service = PrincipalResourceService {
        cal_store: Arc::new(cal_store.await),
        sub_store: Arc::new(sub_store.await),
        auth_provider: Arc::new(auth_provider.await),
        simplified_home_set: false,
    };

    assert!(matches!(
        service
            .get_resource(&("invalid-user".to_owned(),), true)
            .await,
        Err(crate::Error::NotFound)
    ));

    let _principal_resource = service
        .get_resource(&("user".to_owned(),), true)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_propfind() {
    let propfind = PrincipalResource::parse_propfind(
        r#"<?xml version="1.0" encoding="UTF-8"?><propfind xmlns="DAV:"><allprop/></propfind>"#,
    )
    .unwrap();

    let principal = Principal {
        id: "user".to_string(),
        displayname: None,
        principal_type: Individual,
        password: None,
        memberships: vec!["group".to_string()],
    };

    let resource = PrincipalResource {
        principal: principal.clone(),
        members: vec![],
        simplified_home_set: false,
    };

    let response = resource
        .propfind(
            &format!("/caldav/principal/{}", principal.id),
            &propfind.prop,
            propfind.include.as_ref(),
            &CalDavPrincipalUri("/caldav"),
            &principal,
        )
        .unwrap();

    let _output = response.serialize_to_string().unwrap();
}
