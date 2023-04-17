use axum::{body::Body, http::response, response::IntoResponse, routing::get, Router};
use ed25519_dalek::{self, Keypair, PublicKey, SecretKey, Signature, Signer};
use hyper::{self, StatusCode};
use std::fs;

#[tokio::main]
async fn main() {
    let routes = Router::new()
        .route(
            "/",
            get(move |req| srv_file(req)).post(move |req| edwards_test(req)),
        )
        .route("/files/:filename", get(move |req| srv_file(req)));
    match axum::Server::bind(&"127.0.0.1:3000".parse().unwrap())
        .serve(routes.into_make_service())
        .await
    {
        Ok(_a) => {}
        Err(e) => {
            println!("{}", e)
        }
    };
}
async fn edwards_test(req: hyper::Request<Body>) -> impl IntoResponse {
    let (head, _body) = req.into_parts();
    let b64_signature = head.headers.get("x-sec-signature").unwrap();
    let b64_client_public = head.headers.get("x-sec-pubkey").unwrap();
    let b64_client_private = head.headers.get("x-sec-private").unwrap();
    let b64_content = head.headers.get("x-sec-content").unwrap();
    //let b64_client_private_rev = head.headers.get("x-sec-private-rev").unwrap();
    //let b64_client_public_rev = head.headers.get("x-sec-pubkey-rev").unwrap();
    //let b64_signature_rev = head.headers.get("x-sec-signature-rev").unwrap();

    println!("Headers as base64 strings");
    println!("client_private : {}", b64_client_private.to_str().unwrap());
    println!("client_public : {}", b64_client_public.to_str().unwrap());
    println!("signature : {}", b64_signature.to_str().unwrap());

    //println!("client_private_rev : {}",b64_client_private_rev.to_str().unwrap());
    //println!("client_public_rev : {}",b64_client_public_rev.to_str().unwrap());
    //println!("signature_rev : {}",b64_signature_rev.to_str().unwrap());
    println!("content: {}", b64_content.to_str().unwrap());

    let private_decoded_bytes = data_encoding::BASE64
        .decode(b64_client_private.to_str().unwrap().as_bytes())
        .unwrap();
    let public_decoded_bytes = data_encoding::BASE64
        .decode(b64_client_public.to_str().unwrap().as_bytes())
        .unwrap();
    let signature_decoded_bytes = data_encoding::BASE64
        .decode(b64_signature.to_str().unwrap().as_bytes())
        .unwrap();
    let content_decoded_bytes = data_encoding::BASE64
        .decode(b64_content.to_str().unwrap().as_bytes())
        .unwrap();

    //let private_rev_decoded_bytes = data_encoding::BASE64.decode(b64_client_private_rev.to_str().unwrap().as_bytes()).unwrap();
    //let public_rev_decoded_bytes = data_encoding::BASE64.decode(b64_client_public_rev.to_str().unwrap().as_bytes()).unwrap();
    //let signature_rev_decoded_bytes = data_encoding::BASE64.decode(b64_signature_rev.to_str().unwrap().as_bytes()).unwrap();

    println!("Headers as bytes");
    println!("signature_decoded_bytes : {:?}", signature_decoded_bytes);
    println!("public_decoded_bytes : {:?}", public_decoded_bytes);
    println!("private_decoded_bytes : {:?}", private_decoded_bytes);

    //println!("private_rev_decoded_bytes : {:?}",private_rev_decoded_bytes);
    //println!("public_rev_decoded_bytes : {:?}",public_rev_decoded_bytes);
    //println!("signature_rev_decoded_bytes : {:?}",signature_rev_decoded_bytes);
    //println!("content_decoded_bytes: {:?}", content_decoded_bytes);

    let signature = Signature::try_from(signature_decoded_bytes.as_slice()).unwrap();
    let pubkey = PublicKey::from_bytes(&public_decoded_bytes).unwrap();
    let private = SecretKey::from_bytes(&private_decoded_bytes).unwrap();
    let keypair = Keypair {
        public: pubkey,
        secret: SecretKey::from_bytes(&private_decoded_bytes).unwrap(),
    };
    println!("Verify keys as types and back to bytes does not modify them");
    println!(
        "keypair.secret == private && keypair.public == pubkey: {}",
        keypair.secret.to_bytes() == private.to_bytes() && keypair.public == pubkey
    );
    println!(
        "signature as bytes == decoded signature: {:?}",
        signature.to_bytes() == signature_decoded_bytes.as_slice()
    );
    println!(
        "pubkey as bytes == decoded pubkey: {:?}",
        pubkey.as_bytes() == public_decoded_bytes.as_slice()
    );
    println!(
        "private as bytes == decoded private: {:?}",
        private.as_bytes() == private_decoded_bytes.as_slice()
    );

    println!("Does received signature verify?");
    println!(
        "bytes {:?}",
        keypair.verify(&content_decoded_bytes, &signature)
    );
    println!(
        "bytes strict{:?}",
        keypair.verify_strict(&content_decoded_bytes, &signature)
    );

    println!("Internal signing and verification");
    let internal_signature = keypair.sign(&content_decoded_bytes);

    println!(
        "internal signature string: {:?}",
        internal_signature.to_bytes()
    );
    println!(
        "internal verified?: {:?}",
        keypair.verify(&content_decoded_bytes, &internal_signature)
    );
    println!(
        "internal verified strict?: {:?}",
        keypair.verify_strict(&content_decoded_bytes, &internal_signature)
    );

    "".into_response()
}
async fn srv_file(req: hyper::Request<Body>) -> impl IntoResponse {
    if req.uri().path().to_string() == "/".to_string() {
        let index = fs::read("./files/index.html").unwrap();
        let res = response::Builder::new()
            .status(StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE, "text/html")
            .body(Body::from(index))
            .unwrap();
        return res.into_response();
    } else {
        let req_path: &str = req
            .uri()
            .path()
            .split("/")
            .collect::<Vec<&str>>()
            .last()
            .unwrap();
        let m_guess = mime_guess::from_path(req_path);
        let file = fs::read(format!("./files/{}", req_path)).unwrap();
        let res = response::Builder::new()
            .status(StatusCode::OK)
            .header(
                axum::http::header::CONTENT_TYPE,
                m_guess.first().unwrap().to_string(),
            )
            .body(Body::from(file))
            .unwrap();
        return res.into_response();
    };
}
