use reqwest::blocking::{Body, Client};
use serde::Deserialize;
use std::{
    fs::{self, File},
    path::Path,
};

const DRIVE_API: &str = "https://www.googleapis.com/drive/v3";
const DRIVE_UPLOAD_API: &str = "https://www.googleapis.com/upload/drive/v3";

const FCLOAK_FOLDER_NAME: &str = "FCLOAK";
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";

#[derive(Debug, Clone)]
pub struct DriveFile {
    pub id: String,
    pub name: String,
    pub mime_type: Option<String>,
    pub size: Option<String>,
}

impl DriveFile {
    pub fn display_size(&self) -> String {
        let size = self
            .size
            .as_deref()
            .and_then(|value| value.parse::<u64>().ok());

        match size {
            Some(bytes) => format_size(bytes),
            None => "Unknown size".to_string(),
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.name.to_lowercase().ends_with(".fcloak")
    }

    pub fn decrypted_name(&self) -> String {
        self.name
            .strip_suffix(".fcloak")
            .unwrap_or(&self.name)
            .to_string()
    }
}

#[derive(Debug, Deserialize)]
struct DriveFileListResponse {
    #[serde(default)]
    files: Vec<DriveFileResponse>,

    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DriveFileResponse {
    id: String,
    name: String,

    #[serde(rename = "mimeType")]
    mime_type: Option<String>,

    size: Option<String>,
}

pub struct DriveClient {
    access_token: String,
    http: Client,
}

impl DriveClient {
    pub fn new(access_token: String) -> Self {
        Self {
            access_token,
            http: Client::new(),
        }
    }

    fn auth_request(
        &self,
        request: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        request.bearer_auth(&self.access_token)
    }

    fn error_response(
        operation: &str,
        response: reqwest::blocking::Response,
    ) -> Box<dyn std::error::Error> {
        let status = response.status();

        let body = response
            .text()
            .unwrap_or_else(|_| "unable to read response body".to_string());

        format!("Google Drive {operation} failed: {status}: {body}").into()
    }

    fn ensure_folder(&self) -> Result<String, Box<dyn std::error::Error>> {
        let query = format!(
            "name = '{}' and mimeType = '{}' and trashed = false",
            FCLOAK_FOLDER_NAME, FOLDER_MIME
        );

        let response = self
            .auth_request(self.http.get(format!("{DRIVE_API}/files")).query(&[
                ("q", query.as_str()),
                ("spaces", "drive"),
                ("pageSize", "10"),
                ("fields", "files(id,name,mimeType)"),
            ]))
            .send()?;

        if !response.status().is_success() {
            return Err(Self::error_response("folder lookup", response));
        }

        let data: DriveFileListResponse = response.json()?;

        if let Some(folder) = data.files.into_iter().next() {
            return Ok(folder.id);
        }

        let metadata = serde_json::json!({
            "name": FCLOAK_FOLDER_NAME,
            "mimeType": FOLDER_MIME
        });

        let response = self
            .auth_request(
                self.http
                    .post(format!("{DRIVE_API}/files"))
                    .query(&[("fields", "id,name,mimeType")])
                    .json(&metadata),
            )
            .send()?;

        if !response.status().is_success() {
            return Err(Self::error_response("folder creation", response));
        }

        let folder: DriveFileResponse = response.json()?;

        Ok(folder.id)
    }

    pub fn list_files(&self) -> Result<Vec<DriveFile>, Box<dyn std::error::Error>> {
        let folder_id = self.ensure_folder()?;

        let query = format!("'{}' in parents and trashed = false", folder_id);

        let mut page_token: Option<String> = None;
        let mut all_files = Vec::new();

        loop {
            let mut request =
                self.auth_request(self.http.get(format!("{DRIVE_API}/files")).query(&[
                    ("q", query.as_str()),
                    ("fields", "nextPageToken,files(id,name,mimeType,size)"),
                    ("orderBy", "name_natural"),
                    ("pageSize", "100"),
                    ("spaces", "drive"),
                ]));

            if let Some(token) = &page_token {
                request = request.query(&[("pageToken", token)]);
            }

            let response = request.send()?;

            if !response.status().is_success() {
                return Err(Self::error_response("list", response));
            }

            let data: DriveFileListResponse = response.json()?;

            for file in data.files {
                if file.name.to_lowercase().ends_with(".fcloak") {
                    all_files.push(DriveFile {
                        id: file.id,
                        name: file.name,
                        mime_type: file.mime_type,
                        size: file.size,
                    });
                }
            }

            match data.next_page_token {
                Some(token) => page_token = Some(token),
                None => break,
            }
        }

        Ok(all_files)
    }

    pub fn upload_file(&self, path: &Path) -> Result<DriveFile, Box<dyn std::error::Error>> {
        if !path.is_file() {
            return Err("encrypted file does not exist".into());
        }

        let folder_id = self.ensure_folder()?;

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid encrypted filename")?
            .to_string();

        if !file_name.to_lowercase().ends_with(".fcloak") {
            return Err("only FCLOAK encrypted .fcloak files can be uploaded".into());
        }

        let metadata = fs::metadata(path)?;
        let file_size = metadata.len();

        // Google recommends resumable uploads for larger files.
        let response = self
            .auth_request(
                self.http
                    .post(format!("{DRIVE_UPLOAD_API}/files"))
                    .query(&[
                        ("uploadType", "resumable"),
                        ("fields", "id,name,mimeType,size"),
                    ])
                    .header("Content-Type", "application/json; charset=UTF-8")
                    .header("X-Upload-Content-Type", "application/octet-stream")
                    .header("X-Upload-Content-Length", file_size)
                    .json(&serde_json::json!({
                        "name": file_name,
                        "parents": [folder_id]
                    })),
            )
            .send()?;

        if !response.status().is_success() {
            return Err(Self::error_response("upload initialization", response));
        }

        let upload_url = response
            .headers()
            .get(reqwest::header::LOCATION)
            .ok_or("Google Drive did not return an upload URL")?
            .to_str()?
            .to_string();

        let file = File::open(path)?;

        let response = self
            .http
            .put(upload_url)
            .bearer_auth(&self.access_token)
            .header("Content-Type", "application/octet-stream")
            .body(Body::sized(file, file_size))
            .send()?;

        if !response.status().is_success() {
            return Err(Self::error_response("file upload", response));
        }

        let file: DriveFileResponse = response.json()?;

        Ok(DriveFile {
            id: file.id,
            name: file.name,
            mime_type: file.mime_type,
            size: file.size,
        })
    }

    pub fn download_file(
        &self,
        file_id: &str,
        destination: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut response = self
            .auth_request(
                self.http
                    .get(format!("{DRIVE_API}/files/{file_id}"))
                    .query(&[("alt", "media")])
                    .header("Accept", "application/octet-stream"),
            )
            .send()?;

        if !response.status().is_success() {
            return Err(Self::error_response("download", response));
        }

        let temp_path = destination.with_extension("fcloak-download-tmp");

        if temp_path.exists() {
            fs::remove_file(&temp_path)?;
        }

        let result = (|| {
            let mut file = File::create(&temp_path)?;

            let downloaded = std::io::copy(&mut response, &mut file)?;

            file.sync_all()?;

            if downloaded == 0 {
                return Err::<(), Box<dyn std::error::Error>>(
                    "Google Drive returned an empty file".into(),
                );
            }

            fs::rename(&temp_path, destination)?;

            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
            let _ = fs::remove_file(destination);
        }

        result
    }

    pub fn delete_file(&self, file_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let response = self
            .auth_request(self.http.delete(format!("{DRIVE_API}/files/{file_id}")))
            .send()?;

        if !response.status().is_success() {
            return Err(Self::error_response("delete", response));
        }

        Ok(())
    }

    pub fn is_connected(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let response = self
            .auth_request(
                self.http
                    .get(format!("{DRIVE_API}/about"))
                    .query(&[("fields", "user(displayName,emailAddress)")]),
            )
            .send()?;

        Ok(response.status().is_success())
    }
}

fn format_size(size: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let value = size as f64;

    if value >= GB {
        format!("{:.2} GB", value / GB)
    } else if value >= MB {
        format!("{:.2} MB", value / MB)
    } else if value >= KB {
        format!("{:.2} KB", value / KB)
    } else {
        format!("{size} B")
    }
}
