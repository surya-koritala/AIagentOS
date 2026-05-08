use adapters::azure_openai::AzureOpenAiAdapter;
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let kernel = AgentKernelImpl::new().unwrap();
    let adapter = AzureOpenAiAdapter::new(
        "https://roamx-resource.cognitiveservices.azure.com".into(),
        "gpt-5.4".into(),
        std::env::var("AZURE_OPENAI_API_KEY").expect("Set AZURE_OPENAI_API_KEY"),
    )
    .with_api_version("2025-04-01-preview".into());
    kernel.register_provider(Arc::new(adapter)).unwrap();

    let handle = kernel
        .create_agent_full(AgentConfig {
            name: "benchmark".into(),
            task: "benchmark".into(),
            llm_provider: "azure-openai".into(),
            permission_profile: "full-access".into(),
            priority: Priority::default(),
            sandbox_config: None,
        })
        .await
        .unwrap();

    println!("╔═══════════════════════════════════════════╗");
    println!("║  AI Agent OS — Real-World Benchmark Suite ║");
    println!("╚═══════════════════════════════════════════╝\n");

    let mut passed = 0;
    let mut failed = 0;
    let mut total_tokens = 0u32;

    // ─── USE CASE 1: Multi-file project scaffolding ───────────────────
    print!("1. Create a Python project with 3 files... ");
    std::fs::remove_dir_all("/tmp/bench_project").ok();
    let out = kernel.send_message(handle.id,
        "Create a Python project at /tmp/bench_project with: 1) main.py that imports from utils.py and calls a greet function, 2) utils.py with a greet(name) function, 3) requirements.txt with 'requests' in it. Create all 3 files."
    ).await.unwrap();
    total_tokens += out.tokens_used;
    let main_exists = std::path::Path::new("/tmp/bench_project/main.py").exists();
    let utils_exists = std::path::Path::new("/tmp/bench_project/utils.py").exists();
    let req_exists = std::path::Path::new("/tmp/bench_project/requirements.txt").exists();
    if main_exists && utils_exists && req_exists {
        println!("✅ (3 files created, {} tools)", out.tool_calls_made);
        passed += 1;
    } else {
        println!(
            "❌ (missing files: main={} utils={} req={})",
            main_exists, utils_exists, req_exists
        );
        failed += 1;
    }

    // ─── USE CASE 2: Read + analyze + summarize ──────────────────────
    print!("2. Read our README and count features... ");
    let out = kernel.send_message(handle.id,
        "Read /home/surya/AI Agent OS/README.md and tell me exactly how many bullet points are in the Features section. Just the number."
    ).await.unwrap();
    total_tokens += out.tokens_used;
    if out.content.contains("10") || out.content.contains("11") || out.content.contains("12") {
        println!("✅ (found features count: {})", out.content.trim());
        passed += 1;
    } else {
        println!("❌ (got: {})", out.content.trim());
        failed += 1;
    }

    // ─── USE CASE 3: Debug a runtime error ───────────────────────────
    print!("3. Debug a Python runtime error... ");
    std::fs::write(
        "/tmp/bench_bugpy.py",
        "def factorial(n):\n    return n * factorial(n-1)\n\nprint(factorial(5))",
    )
    .unwrap();
    let out = kernel.send_message(handle.id,
        "Read /tmp/bench_bugpy.py, identify the bug (it will cause infinite recursion), fix it, and write the fixed version back. The base case is missing."
    ).await.unwrap();
    total_tokens += out.tokens_used;
    let fixed = std::fs::read_to_string("/tmp/bench_bugpy.py").unwrap_or_default();
    if fixed.contains("n <= 1")
        || fixed.contains("n == 0")
        || fixed.contains("n == 1")
        || fixed.contains("n < 2")
    {
        println!("✅ (base case added, {} tools)", out.tool_calls_made);
        passed += 1;
    } else {
        println!(
            "❌ (no base case found in: {})",
            &fixed[..fixed.len().min(80)]
        );
        failed += 1;
    }

    // ─── USE CASE 4: System administration task ──────────────────────
    print!("4. Check disk space and report... ");
    let out = kernel
        .send_message(
            handle.id,
            "Run 'df -h /' and tell me the percentage of disk used. Just the percentage number.",
        )
        .await
        .unwrap();
    total_tokens += out.tokens_used;
    if out.content.contains('%') || out.content.chars().any(|c| c.is_ascii_digit()) {
        println!("✅ ({})", out.content.trim());
        passed += 1;
    } else {
        println!("❌ (got: {})", out.content.trim());
        failed += 1;
    }

    // ─── USE CASE 5: Web research ────────────────────────────────────
    print!("5. Fetch and parse JSON from API... ");
    let out = kernel.send_message(handle.id,
        "Fetch https://httpbin.org/json using http_get and tell me the title of the slideshow. Just the title, nothing else."
    ).await.unwrap();
    total_tokens += out.tokens_used;
    if out.content.to_lowercase().contains("sample") || out.content.to_lowercase().contains("slide")
    {
        println!("✅ ({})", out.content.trim());
        passed += 1;
    } else {
        println!("❌ (got: {})", out.content.trim());
        failed += 1;
    }

    // ─── USE CASE 6: Multi-step with dependencies ────────────────────
    print!("6. Create file, read it back, modify it... ");
    std::fs::remove_file("/tmp/bench_chain.txt").ok();
    let out = kernel.send_message(handle.id,
        "1) Write 'hello' to /tmp/bench_chain.txt, 2) Read it back to confirm, 3) Append ' world' to it. Do all three steps."
    ).await.unwrap();
    total_tokens += out.tokens_used;
    let content = std::fs::read_to_string("/tmp/bench_chain.txt").unwrap_or_default();
    if content.contains("hello") && content.contains("world") {
        println!(
            "✅ (file contains 'hello world', {} tools)",
            out.tool_calls_made
        );
        passed += 1;
    } else {
        println!("❌ (file contains: '{}')", content.trim());
        failed += 1;
    }

    // ─── USE CASE 7: Memory across turns ─────────────────────────────
    print!("7. Remember info across conversation turns... ");
    let _ = kernel
        .send_message(handle.id, "Remember: the project deadline is March 15th.")
        .await
        .unwrap();
    let _ = kernel
        .send_message(handle.id, "What is 42 * 7?")
        .await
        .unwrap(); // distractor
    let out = kernel
        .send_message(handle.id, "When is the project deadline?")
        .await
        .unwrap();
    total_tokens += out.tokens_used;
    if out.content.contains("March 15") || out.content.contains("March fifteenth") {
        println!("✅ (remembered: {})", out.content.trim());
        passed += 1;
    } else {
        println!("❌ (got: {})", out.content.trim());
        failed += 1;
    }

    // ─── USE CASE 8: Error recovery ──────────────────────────────────
    print!("8. Handle nonexistent file gracefully... ");
    let out = kernel.send_message(handle.id,
        "Try to read /tmp/this_file_definitely_does_not_exist_xyz.txt and tell me what happened."
    ).await.unwrap();
    total_tokens += out.tokens_used;
    if out.content.to_lowercase().contains("not found")
        || out.content.to_lowercase().contains("doesn't exist")
        || out.content.to_lowercase().contains("does not exist")
        || out.content.to_lowercase().contains("no such")
        || out.content.to_lowercase().contains("error")
    {
        println!("✅ (handled gracefully)");
        passed += 1;
    } else {
        println!("❌ (got: {})", &out.content[..out.content.len().min(60)]);
        failed += 1;
    }

    // ─── USE CASE 9: Code generation + execution ─────────────────────
    print!("9. Write and run a bash script... ");
    std::fs::remove_file("/tmp/bench_script.sh").ok();
    std::fs::remove_file("/tmp/bench_output.txt").ok();
    let out = kernel.send_message(handle.id,
        "Write a bash script to /tmp/bench_script.sh that outputs 'BENCHMARK_OK' to /tmp/bench_output.txt, then run it with 'bash /tmp/bench_script.sh'"
    ).await.unwrap();
    total_tokens += out.tokens_used;
    let output = std::fs::read_to_string("/tmp/bench_output.txt").unwrap_or_default();
    if output.contains("BENCHMARK_OK") {
        println!("✅ (script ran, output verified)");
        passed += 1;
    } else {
        println!("❌ (output file: '{}')", output.trim());
        failed += 1;
    }

    // ─── USE CASE 10: Complex reasoning ──────────────────────────────
    print!("10. Solve a logic puzzle... ");
    let out = kernel.send_message(handle.id,
        "If a train leaves at 9:00 AM going 60 mph, and another leaves the same station at 10:00 AM going 90 mph in the same direction, at what time does the second train catch up? Just give the time."
    ).await.unwrap();
    total_tokens += out.tokens_used;
    if out.content.contains("12:00")
        || out.content.contains("noon")
        || out.content.contains("12 PM")
        || out.content.contains("12:00 PM")
    {
        println!("✅ ({})", out.content.trim());
        passed += 1;
    } else {
        println!("❌ (got: {})", out.content.trim());
        failed += 1;
    }

    // ─── Results ─────────────────────────────────────────────────────
    println!("\n╔═══════════════════════════════════════════╗");
    println!(
        "║  Results: {}/{} passed                      ║",
        passed,
        passed + failed
    );
    println!(
        "║  Total tokens: {} (~${:.3})        ║",
        total_tokens,
        total_tokens as f64 * 0.00001
    );
    println!("╚═══════════════════════════════════════════╝");

    if failed > 0 {
        std::process::exit(1);
    }
}
