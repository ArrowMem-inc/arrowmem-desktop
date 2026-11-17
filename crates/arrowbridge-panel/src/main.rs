//! Thin entry: one line on stdout, exit 0 on every path, no panic message.
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = std::panic::catch_unwind(|| arrowbridge_panel::run(&args)).unwrap_or_else(|_| arrowbridge_panel::UNKNOWN_STATE.to_string());
    println!("{out}");
}
