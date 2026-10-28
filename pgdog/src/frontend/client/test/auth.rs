//! Client authentication tests.

use std::time::Duration;

use pgdog_config::{AuthType, PassthroughAuth, users::PasswordKind};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

use crate::{
    auth::{AuthResult, scram::Client as ScramClient},
    config::{config, set},
    expect_message,
    frontend::{Client, Error},
    net::{Authentication, ErrorResponse, FromBytes, Parameters, Password, Query, Stream, ToBytes},
};

use super::SpawnedClient;

async fn scram_connection() -> (JoinHandle<Result<AuthResult, Error>>, Stream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let connection = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept connection");
        Client::check_password(
            &mut Stream::plain(socket, 4096),
            "user",
            "database",
            &AuthType::Scram,
            &[PasswordKind::Plain("pgdog".to_string())],
        )
        .await
    });
    let peer = TcpStream::connect(address).await.expect("connect peer");
    let mut peer = Stream::plain(peer, 4096);
    let challenge = peer.read().await.expect("SCRAM challenge");
    assert!(matches!(
        Authentication::from_bytes(challenge.to_bytes()).expect("parse challenge"),
        Authentication::Sasl(_)
    ));
    (connection, peer)
}

async fn scram_client_first<'a>(peer: &mut Stream, password: &'a str) -> ScramClient<'a> {
    let mut client = ScramClient::new("user", password);
    peer.send_flush(&Password::sasl_initial(
        &client.first().expect("client first"),
    ))
    .await
    .expect("send client first");
    let response = peer.read().await.expect("server first");
    let Authentication::SaslContinue(data) =
        Authentication::from_bytes(response.to_bytes()).expect("parse server first")
    else {
        panic!("expected SASLContinue");
    };
    client.server_first(&data).expect("accept server first");
    client
}

async fn auth_result(
    connection: JoinHandle<Result<AuthResult, Error>>,
) -> Result<AuthResult, Error> {
    timeout(Duration::from_secs(5), connection)
        .await
        .expect("authentication must finish")
        .expect("authentication task")
}

#[tokio::test]
async fn test_scram_password_disconnect_before_initial_response() {
    let (connection, peer) = scram_connection().await;
    drop(peer);
    let error = auth_result(connection)
        .await
        .expect_err("disconnect is not a wrong password");
    assert!(error.disconnect(), "expected disconnect, got {error:?}");
}

#[tokio::test]
async fn test_scram_password_disconnect_before_client_final() {
    let (connection, mut peer) = scram_connection().await;
    scram_client_first(&mut peer, "pgdog").await;
    drop(peer);
    let error = auth_result(connection)
        .await
        .expect_err("disconnect is not a wrong password");
    assert!(error.disconnect(), "expected disconnect, got {error:?}");
}

#[tokio::test]
async fn test_scram_password_preserves_protocol_error() {
    let (connection, mut peer) = scram_connection().await;
    peer.send_flush(&Query::new("SELECT 1"))
        .await
        .expect("send unexpected message");
    assert!(matches!(
        auth_result(connection).await,
        Err(Error::UnexpectedMessage('Q'))
    ));
}

#[tokio::test]
async fn test_scram_password_still_checks_client_proof() {
    for (password, expected) in [
        ("pgdog", AuthResult::Ok),
        ("wrong", AuthResult::NoPasswordMatch),
    ] {
        let (connection, mut peer) = scram_connection().await;
        let mut client = scram_client_first(&mut peer, password).await;
        peer.send_flush(&Password::PasswordMessage {
            response: client.last().expect("client final"),
        })
        .await
        .expect("send client final");
        assert_eq!(
            auth_result(connection)
                .await
                .expect("authentication result"),
            expected
        );
    }
}

/// Connect to the admin database and answer the plaintext password
/// request with the given password.
async fn login_admin(password: &str) -> SpawnedClient {
    let cfg = config();
    let mut params = Parameters::default();
    params.insert("user", cfg.config.admin.user.as_str());
    params.insert("database", cfg.config.admin.name.as_str());

    let mut client = SpawnedClient::new_with_login(params).await;

    // Both the admin and the passthrough branches request the password
    // in plaintext; what matters is what happens with the answer.
    let request = expect_message!(client.read().await, Authentication);
    assert!(matches!(request, Authentication::ClearTextPassword));

    client.send(Password::new_password(password)).await;
    client
}

/// Admin connections must be authenticated against the admin password even
/// when passthrough auth is enabled. Regression test for the passthrough
/// branch running first and accepting any password for the admin database.
#[tokio::test]
async fn test_admin_password_checked_with_passthrough_auth() {
    crate::logger();
    crate::config::load_test();

    let mut cfg = (*config()).clone();
    cfg.config.general.auth_type = AuthType::Plain;
    cfg.config.general.passthrough_auth = PassthroughAuth::EnabledPlain;
    cfg.config.admin.password = "admin-password".into();
    set(cfg).unwrap();

    // The wrong password is rejected instead of being passed through.
    let mut client = login_admin("not-the-admin-password").await;
    let error = ErrorResponse::try_from(client.read().await).unwrap();
    assert_eq!(error.code, "28000");
    client.join().await;

    // The correct password is accepted.
    let mut client = login_admin("admin-password").await;
    let response = expect_message!(client.read().await, Authentication);
    assert!(matches!(response, Authentication::Ok));
    client.read_until('Z').await;
    client.join().await;
}
