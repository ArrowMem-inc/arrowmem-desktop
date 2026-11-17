//! Thin entry: one line on stdout, exit 0 on every path, no panic message.
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let unknown = || arrowbridge_panel::UNKNOWN_STATE.to_string();
    let out = std::panic::catch_unwind(|| {
        let args: Option<Vec<String>> = std::env::args_os().skip(1).map(|a| a.into_string().ok()).collect();
        args.map_or_else(unknown, |a| arrowbridge_panel::run(&a))
    })
    .unwrap_or_else(|_| unknown());
    println!("{out}");
}
