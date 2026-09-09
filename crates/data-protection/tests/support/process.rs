use std::{
    io,
    process::{Child, Command, ExitStatus, Stdio},
    time::Duration,
};

pub fn command(program: &str, limit: Duration) -> Command {
    let mut command = Command::new("python3");
    command
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/watchdog.py"
        ))
        .arg(limit.as_secs_f64().to_string())
        .arg(program);
    command
}

struct Watchdog(Child);
impl Drop for Watchdog {
    fn drop(&mut self) {
        // Closing the liveness pipe asks the isolated watchdog to retire its entire tree.
        // Abrupt termination of this Rust process closes the same handle in the kernel.
        self.0.stdin.take();
        let _ = self.0.wait();
    }
}

pub fn run(command: &mut Command) -> io::Result<ExitStatus> {
    let mut watchdog = Watchdog(command.stdin(Stdio::piped()).spawn()?);
    watchdog.0.wait()
}

#[cfg(unix)]
#[test]
fn parent_exit_and_timeout_release_descendant_handles() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, Read};
    for timeout in [false, true] {
        let limit = if timeout {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(60)
        };
        let mut watchdog = Watchdog(
            command("/bin/sh", limit)
                .args(["-c", "sleep 60 & echo ready; wait"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let stdout = watchdog.0.stdout.take().ok_or("missing output")?;
        let (ready_send, ready) = std::sync::mpsc::channel();
        let (done_send, done) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut output = io::BufReader::new(stdout);
            let mut line = String::new();
            let _ = ready_send.send(output.read_line(&mut line));
            let _ = done_send.send(output.read_to_end(&mut Vec::new()));
        });
        ready.recv_timeout(Duration::from_secs(3))??;
        if !timeout {
            watchdog.0.stdin.take();
        }
        let ended = done.recv_timeout(Duration::from_secs(3));
        let status = watchdog.0.wait()?;
        assert!(
            ended.is_ok(),
            "descendant retained output after parent EOF/deadline"
        );
        ended??;
        assert_eq!(status.code(), Some(if timeout { 124 } else { 130 }));
        reader.join().map_err(|_| "output reader panicked")?;
    }
    Ok(())
}
