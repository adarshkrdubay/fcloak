use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=FCLOAK_GOOGLE_CLIENT_ID");
    println!("cargo:rerun-if-env-changed=FCLOAK_GOOGLE_CLIENT_SECRET");
    println!("cargo:rerun-if-changed=assets/fcloak.ico");

    let client_id = env::var("FCLOAK_GOOGLE_CLIENT_ID")
        .expect("FCLOAK_GOOGLE_CLIENT_ID must be set when building fcloak-gui");

    let client_secret = env::var("FCLOAK_GOOGLE_CLIENT_SECRET")
        .expect("FCLOAK_GOOGLE_CLIENT_SECRET must be set when building fcloak-gui");

    if client_id.trim().is_empty() {
        panic!("FCLOAK_GOOGLE_CLIENT_ID cannot be empty");
    }

    if client_secret.trim().is_empty() {
        panic!("FCLOAK_GOOGLE_CLIENT_SECRET cannot be empty");
    }

    println!("cargo:rustc-env=FCLOAK_GOOGLE_CLIENT_ID={client_id}");
    println!("cargo:rustc-env=FCLOAK_GOOGLE_CLIENT_SECRET={client_secret}");

    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();

        res.set_icon("assets/fcloak.ico");

        res.compile()
            .expect("failed to compile Windows resources");
    }
}