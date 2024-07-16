use std::sync::mpsc;
use log::error;
use serde::Serialize;
use warp::Filter;
use warp::ws::{Message, WebSocket};

#[derive(Serialize)]
pub struct LogMessage {
    level: String,
    message: String,
}

async fn websocket_handler(ws: WebSocket, rx: mpsc::Receiver<LogMessage>) {
    let (mut tx_ws, _) = ws.split();

    // Forward log messages to the websocket
    while let Some(log_message) = rx.recv().await {
        let log_message = serde_json::to_string(&log_message).unwrap();
        let log_message = Message::text(log_message);
        if tx_ws.send(log_message).await.is_err() {
            error!("Error when sending LogMessage: {:?}", log_message);
        }
    }
}

/// Spawns a new thread
pub fn start_websocket_server(tx: mpsc::Sender<LogMessage>) {
    std::thread::spawn(async move || {
        let route = warp::path("ws")
            .and(warp::ws())
            .map(move |ws: warp::ws::Ws| {
                let (client_tx, client_rx) = mpsc::channel();
                let tx = tx.clone();
                tokio::spawn(async move {
                    if tx.send(LogMessage { level: "error".to_string(), message: "error".to_string() }).await.is_err() {
                        error!("Failed to register websocket client");
                    }
                });
                ws.on_upgrade(move |socket| websocket_handler(socket, client_rx))
            });

        warp::serve(route)
            .run(([127, 0, 0, 1], 3030)).await
    });
}
