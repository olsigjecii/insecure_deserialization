use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};

// --- Data Structures ---

// The base request structure that contains the Base64 encoded player state.

#[derive(Deserialize)]
struct GameStateRequest {
    #[serde(rename = "playerState")]
    player_state: String,
}

// Represents the game's location data.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Location {
    x: i32,
    y: i32,
    zone: String,
}

// Represents the player's equipment.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Equipment {
    // In a real app, this might be a Vec<u32> of item IDs.
    // We use a fixed-size array to match the lesson's example.
    items: [u32; 5],
}

// --- VULNERABLE Implementation ---

// VULNERABLE: This struct is too permissive. An attacker can add unexpected
// fields to the JSON payload, and serde will deserialize them without error.
// The application logic might then insecurely act upon this untrusted data.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct VulnerablePlayerState {
    equipment: Equipment,
    location: Location,
    // This is our "gadget". The frontend client never sends this, but an
    // attacker can inject it into the serialized data. The backend foolishly
    // trusts it.
    is_admin: Option<bool>,
    gold: Option<u32>,
}

// VULNERABLE endpoint handler
async fn vulnerable_state_update(
    user_id: web::Path<u32>,
    req_body: web::Json<GameStateRequest>,
) -> impl Responder {
    // 1. Decode the Base64 data from the request
    let decoded_bytes = match general_purpose::STANDARD.decode(&req_body.player_state) {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::BadRequest().body("Invalid Base64 data"),
    };

    // 2. Deserialize the JSON into our VULNERABLE struct
    // Serde will happily deserialize any fields present in the JSON, including
    // the unexpected `is_admin` and `gold` fields.
    let player_state: VulnerablePlayerState = match serde_json::from_slice(&decoded_bytes) {
        Ok(state) => state,
        Err(e) => {
            return HttpResponse::BadRequest().body(format!("JSON Deserialization Error: {}", e));
        }
    };

    println!(
        "[VULNERABLE] Received state for user {}: {:?}",
        user_id, player_state
    );

    // 3. **THE FLAW**: The application logic now checks for the presence of the
    // attacker-injected fields and acts on them.
    let mut response_message = format!(
        "Player state for user {} updated. Sword level is now: {}.",
        user_id, player_state.equipment.items[2]
    );

    if let Some(true) = player_state.is_admin {
        let admin_msg = "\nALERT: Attacker successfully escalated privileges to ADMIN!";
        println!("{}", admin_msg);
        response_message.push_str(admin_msg);
    }
    if let Some(gold_amount) = player_state.gold {
        let gold_msg = &format!("\nALERT: Attacker granted themselves {} gold!", gold_amount);
        println!("{}", gold_msg);
        response_message.push_str(gold_msg);
    }

    HttpResponse::Ok().body(response_message)
}

// --- SECURE Implementation ---

// SECURE: This struct is hardened against unexpected data.
#[derive(Serialize, Deserialize, Debug)]
// `deny_unknown_fields` is the key mitigation. It tells serde to reject
// any data that contains fields not explicitly defined in the struct.
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct SecurePlayerState {
    equipment: Equipment,
    location: Location,
    // Note: The `is_admin` and `gold` fields are NOT defined here.
}

// SECURE endpoint handler
async fn secure_state_update(
    user_id: web::Path<u32>,
    req_body: web::Json<GameStateRequest>,
) -> impl Responder {
    // 1. Decode the Base64 data
    let decoded_bytes = match general_purpose::STANDARD.decode(&req_body.player_state) {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::BadRequest().body("Invalid Base64 data"),
    };

    // 2. **THE FIX**: Attempt to deserialize the JSON into our SECURE struct.
    // If the incoming JSON contains extra fields like `is_admin` or `gold`,
    // the `deny_unknown_fields` attribute will cause deserialization to FAIL.
    let player_state: SecurePlayerState = match serde_json::from_slice(&decoded_bytes) {
        Ok(state) => state,
        Err(e) => {
            // The attack is caught here!
            let error_msg = format!(
                "MITIGATED: Payload rejected due to unexpected fields. Error: {}",
                e
            );
            println!("{}", error_msg);
            return HttpResponse::BadRequest().body(error_msg);
        }
    };

    // 3. Further Validation: Even with known fields, we should validate the values.
    if player_state.equipment.items[2] > 20 {
        // Max sword level is 20
        let error_msg = "MITIGATED: Invalid item level detected. Sword level cannot exceed 20.";
        println!("{}", error_msg);
        return HttpResponse::UnprocessableEntity().body(error_msg);
    }

    println!(
        "[SECURE] Received and validated state for user {}: {:?}",
        user_id, player_state
    );

    let response_message = format!(
        "Player state for user {} securely updated. Sword level is now: {}.",
        user_id, player_state.equipment.items[2]
    );

    HttpResponse::Ok().body(response_message)
}

// --- Server Setup ---
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Starting 'Dungeons and Money' API server at http://127.0.0.1:8080");

    HttpServer::new(|| {
        App::new()
            // VULNERABLE route
            .route(
                "/vulnerable/state/{user_id}",
                web::post().to(vulnerable_state_update),
            )
            // SECURE route
            .route(
                "/secure/state/{user_id}",
                web::post().to(secure_state_update),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
