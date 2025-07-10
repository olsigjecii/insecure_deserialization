# Lesson: Insecure Deserialization in Rust

In this lesson, we explore the dangers of insecure deserialization, a vulnerability where an application blindly trusts and processes serialized data from a client without proper validation. We will demonstrate this using a Rust web application built with the actix_web framework, showing how an attacker can manipulate the application's state and escalate privileges. Finally, we will implement a robust mitigation using features provided by the serde library.

The scenario is based on a fictional game, "Dungeons and Money," where your player state is saved to a server. We will put on our hacker hats to give ourselves an unfair advantage!

📜 Concepts Summary
Serialization: The process of converting data structures (like a Rust struct) into a format (like JSON) suitable for storage or transmission.


Deserialization: The reverse process of converting a format like JSON back into a native data structure. 


Insecure Deserialization: A vulnerability that occurs when an application deserializes data controlled by an attacker without sufficient validation, potentially leading to data tampering, logic abuse, or even remote code execution. 

The "Gadget": In the context of deserialization attacks, a "gadget" is a piece of code or a logic path in the application that can be triggered or manipulated by the deserialization process. In our Rust example, the gadget isn't RCE (as serde_json is safe in that regard), but rather business logic that foolishly trusts extra, attacker-supplied fields in the deserialized object (is_admin: true).

⚙️ Setting up the Demo Application
Prerequisites
Install the Rust toolchain: https://www.rust-lang.org/tools/install

Step 1: Create the Project
In your terminal, create a new Rust project:

Bash

cargo new rust-insecure-deserialization-lesson
cd rust-insecure-deserialization-lesson
Step 2: Define Dependencies
Replace the contents of Cargo.toml with the following:

Ini, TOML

[package]
name = "rust-insecure-deserialization-lesson"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.21"
Step 3: Add the Application Code
Replace the contents of src/main.rs with the Rust code provided in the lesson above.

Step 4: Build and Run the Application
From your project's root directory, run the following command:

Bash

cargo run
You should see the output: 🚀 Starting 'Dungeons and Money' API server at http://127.0.0.1:8080. The server is now ready to accept requests.

⚔️ Vulnerability Demonstration
We will now interact with the vulnerable endpoint to manipulate the game state and grant ourselves admin privileges.

Step 1: Create a Malicious Payload
The original, legitimate playerState object looks like this in JSON format:
{"equipment":{"items":[0,0,1,0,0]},"location":{"x":12,"y":15,"zone":"Starting Area"}}

Our malicious payload will do two things:

Upgrade our sword's level from 

1 to 99. 

Inject new fields, is_admin and gold, that the server-side VulnerablePlayerState struct will blindly deserialize.

Here is our malicious JSON object:

JSON

{
  "equipment": {
    "items": [0, 0, 99, 0, 0]
  },
  "location": {
    "x": 12,
    "y": 15,
    "zone": "Starting Area"
  },
  "is_admin": true,
  "gold": 50000
}
Step 2: Base64 Encode the Payload
API requests expect this JSON to be Base64 encoded.  You can use an online tool or the following command to encode it:


Bash

echo '{"equipment":{"items":[0,0,99,0,0]},"location":{"x":12,"y":15,"zone":"Starting Area"},"is_admin":true,"gold":50000}' | base64
This will produce the following encoded string:
eyJlcXVpcG1lbnQiOnsiaXRlbXMiOlswLDAsOTksMCwwXX0sImxvY2F0aW9uIjp7IngiOjEyLCJ5IjoxNSwiem9uZSI6IlN0YXJ0aW5nIEFyZWEifSwiaXNfYWRtaW4iOnRydWUsImdvbGQiOjUwMDAwfQo=

Step 3: Send the Malicious Request
Now, use 

curl to send this payload to the /vulnerable/state/147983414 endpoint. 

Bash

curl -X POST \
  http://127.0.0.1:8080/vulnerable/state/147983414 \
  -H 'Content-Type: application/json' \
  -d '{
    "playerState": "eyJlcXVpcG1lbnQiOnsiaXRlbXMiOlswLDAsOTksMCwwXX0sImxvY2F0aW9uIjp7IngiOjEyLCJ5IjoxNSwiem9uZSI6IlN0YXJ0aW5nIEFyZWEifSwiaXNfYWRtaW4iOnRydWUsImdvbGQiOjUwMDAwfQo="
  }'
Step 4: Observe the Exploit
The curl command will return a successful response:
Player state for user 147983414 updated. Sword level is now: 99. ALERT: Attacker successfully escalated privileges to ADMIN! ALERT: Attacker granted themselves 50000 gold!

Check the terminal where your cargo run command is executing. You will see the server-side logs confirming the successful attack:

[VULNERABLE] Received state for user 147983414: VulnerablePlayerState { equipment: Equipment { items: [0, 0, 99, 0, 0] }, location: Location { x: 12, y: 15, zone: "Starting Area" }, is_admin: Some(true), gold: Some(50000) }
ALERT: Attacker successfully escalated privileges to ADMIN!
ALERT: Attacker granted themselves 50000 gold!
Success! The vulnerable server deserialized our entire payload, and the flawed business logic acted upon the unexpected data, granting us admin rights and gold.

##🛡️ Mitigation Demonstration

Now, we will send the exact same malicious payload to the /secure endpoint to show how proper security controls prevent the attack.

Step 1: Send the Request to the Secure Endpoint
Use curl to target /secure/state/147983414 with the same body as before.

Bash

curl -X POST \
  http://127.0.0.1:8080/secure/state/147983414 \
  -H 'Content-Type: application/json' \
  -d '{
    "playerState": "eyJlcXVpcG1lbnQiOnsiaXRlbXMiOlswLDAsOTksMCwwXX0sImxvY2F0aW9uIjp7IngiOjEyLCJ5IjoxNSwiem9uZSI6IlN0YXJ0aW5nIEFyZWEifSwiaXNfYWRtaW4iOnRydWUsImdvbGQiOjUwMDAwfQo="
  }'
Step 2: Observe the Mitigation
This time, the server rejects the request with an HTTP 400 Bad Request error. The curl output will be:

MITIGATED: Payload rejected due to unexpected fields. Error: unknown field is_admin, expected equipmentorlocation at line 8 column 3

The terminal running the server will also show that the attack was caught and blocked:

MITIGATED: Payload rejected due to unexpected fields. Error: unknown field is_admin, expected equipmentorlocation at line 8 column 3

The Fix: #[serde(deny_unknown_fields)]
The mitigation was achieved by adding a single attribute to our secure data structure:

Rust

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)] // This is the fix!
#[serde(rename_all = "camelCase")]
struct SecurePlayerState {
    equipment: Equipment,
    location: Location,
}
This powerful attribute instructs serde to strictly enforce the schema. If any fields not defined in SecurePlayerState (like is_admin or gold) are present in the incoming JSON, serde will immediately fail the deserialization process. This is the most effective way to prevent parameter injection attacks via deserialization in Rust.