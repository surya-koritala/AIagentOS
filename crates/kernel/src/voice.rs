//! Voice I/O — speech-to-text and text-to-speech for agents.
//!
//! Integrates with Azure Speech Services or OpenAI Whisper/TTS.

use serde::{Deserialize, Serialize};

/// Voice configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceConfig {
    pub stt_provider: SttProvider,
    pub tts_provider: TtsProvider,
    pub language: String,
    pub voice_name: Option<String>,
}

impl Default for VoiceConfig {
    fn default() -> Self {
        Self {
            stt_provider: SttProvider::OpenAiWhisper,
            tts_provider: TtsProvider::OpenAiTts,
            language: "en".into(),
            voice_name: Some("alloy".into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SttProvider { OpenAiWhisper, AzureSpeech }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TtsProvider { OpenAiTts, AzureSpeech }

/// Speech-to-text: convert audio to text.
pub async fn speech_to_text(audio_path: &str, config: &VoiceConfig) -> Result<String, String> {
    let audio_bytes = std::fs::read(audio_path).map_err(|e| format!("Can't read audio: {}", e))?;

    match config.stt_provider {
        SttProvider::OpenAiWhisper => whisper_stt(&audio_bytes).await,
        SttProvider::AzureSpeech => azure_stt(&audio_bytes, &config.language).await,
    }
}

/// Text-to-speech: convert text to audio file.
pub async fn text_to_speech(text: &str, output_path: &str, config: &VoiceConfig) -> Result<(), String> {
    let audio = match config.tts_provider {
        TtsProvider::OpenAiTts => openai_tts(text, config.voice_name.as_deref().unwrap_or("alloy")).await?,
        TtsProvider::AzureSpeech => azure_tts(text, &config.language).await?,
    };
    std::fs::write(output_path, &audio).map_err(|e| format!("Can't write audio: {}", e))
}

async fn whisper_stt(audio: &[u8]) -> Result<String, String> {
    let api_key = std::env::var("OPENAI_API_KEY").map_err(|_| "OPENAI_API_KEY not set")?;
    let client = reqwest::Client::new();

    let part = reqwest::multipart::Part::bytes(audio.to_vec())
        .file_name("audio.wav")
        .mime_str("audio/wav").unwrap();
    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("model", "whisper-1");

    let resp = client.post("https://api.openai.com/v1/audio/transcriptions")
        .header("Authorization", format!("Bearer {}", api_key))
        .multipart(form)
        .send().await.map_err(|e| e.to_string())?;

    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    json["text"].as_str().map(|s| s.to_string()).ok_or("No text in response".into())
}

async fn openai_tts(text: &str, voice: &str) -> Result<Vec<u8>, String> {
    let api_key = std::env::var("OPENAI_API_KEY").map_err(|_| "OPENAI_API_KEY not set")?;
    let client = reqwest::Client::new();

    let resp = client.post("https://api.openai.com/v1/audio/speech")
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&serde_json::json!({"model": "tts-1", "input": text, "voice": voice}))
        .send().await.map_err(|e| e.to_string())?;

    resp.bytes().await.map(|b| b.to_vec()).map_err(|e| e.to_string())
}

async fn azure_stt(audio: &[u8], language: &str) -> Result<String, String> {
    let key = std::env::var("AZURE_SPEECH_KEY").map_err(|_| "AZURE_SPEECH_KEY not set")?;
    let region = std::env::var("AZURE_SPEECH_REGION").unwrap_or_else(|_| "eastus".into());
    let client = reqwest::Client::new();

    let resp = client.post(format!("https://{}.stt.speech.microsoft.com/speech/recognition/conversation/cognitiveservices/v1?language={}", region, language))
        .header("Ocp-Apim-Subscription-Key", &key)
        .header("Content-Type", "audio/wav")
        .body(audio.to_vec())
        .send().await.map_err(|e| e.to_string())?;

    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    json["DisplayText"].as_str().map(|s| s.to_string()).ok_or("No text in response".into())
}

async fn azure_tts(text: &str, language: &str) -> Result<Vec<u8>, String> {
    let key = std::env::var("AZURE_SPEECH_KEY").map_err(|_| "AZURE_SPEECH_KEY not set")?;
    let region = std::env::var("AZURE_SPEECH_REGION").unwrap_or_else(|_| "eastus".into());
    let client = reqwest::Client::new();

    let ssml = format!("<speak version='1.0' xml:lang='{}'><voice name='en-US-JennyNeural'>{}</voice></speak>", language, text);
    let resp = client.post(format!("https://{}.tts.speech.microsoft.com/cognitiveservices/v1", region))
        .header("Ocp-Apim-Subscription-Key", &key)
        .header("Content-Type", "application/ssml+xml")
        .header("X-Microsoft-OutputFormat", "audio-16khz-128kbitrate-mono-mp3")
        .body(ssml)
        .send().await.map_err(|e| e.to_string())?;

    resp.bytes().await.map(|b| b.to_vec()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = VoiceConfig::default();
        assert_eq!(cfg.language, "en");
        assert!(cfg.voice_name.is_some());
    }
}
