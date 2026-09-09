use std::{
    io,
    process::{Child, Command, ExitStatus, Stdio},
    time::Duration,
};

struct ProcessTree(Option<Child>);
impl ProcessTree {
    fn spawn(command: &mut Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        Ok(Self(Some(command.spawn()?)))
    }
    fn terminate(&mut self) -> io::Result<()> {
        if let Some(mut child) = self.0.take() {
            // The leader stays unreaped while signalling its group, preventing PID reuse.
            #[cfg(unix)]
            let killed = Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{}", child.id())])
                .stderr(Stdio::null())
                .status();
            #[cfg(windows)]
            let killed = Command::new("taskkill")
                .args(["/F", "/T", "/PID", &child.id().to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            #[cfg(not(any(unix, windows)))]
            let killed: io::Result<ExitStatus> = Err(io::Error::other("unsupported probe host"));
            if !killed.is_ok_and(|status| status.success()) {
                if child.try_wait()?.is_some() {
                    return Ok(());
                }
                child.kill()?;
                child.wait()?;
                return Err(io::Error::other("failed to terminate probe process tree"));
            }
            child.wait()?;
        }
        Ok(())
    }
}
impl Drop for ProcessTree {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

pub async fn run(command: &mut Command, limit: Duration) -> io::Result<ExitStatus> {
    ProcessTree::spawn(command)?.wait(limit).await
}

impl ProcessTree {
    async fn wait(&mut self, limit: Duration) -> io::Result<ExitStatus> {
        let outcome = {
            let wait = async {
                loop {
                    let child = self
                        .0
                        .as_mut()
                        .ok_or_else(|| io::Error::other("missing process"))?;
                    if let Some(status) = child.try_wait()? {
                        self.0.take();
                        return Ok(status);
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            };
            tokio::select! {
                result = tokio::time::timeout(limit, wait) => result.unwrap_or_else(|_| {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "probe process tree exceeded deadline"))
                }),
                signal = cancelled() => {
                    signal?;
                    Err(io::Error::new(io::ErrorKind::Interrupted, "probe process cancelled"))
                }
            }
        };
        if outcome.is_err() {
            self.terminate()?;
        }
        outcome
    }
}

async fn cancelled() -> io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        tokio::select! { _ = term.recv() => {}, _ = interrupt.recv() => {} }
        Ok(())
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

#[cfg(unix)]
#[tokio::test]
async fn early_exit_and_timeout_release_descendant_handles()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, Read};
    for timeout in [false, true] {
        let mut tree = ProcessTree::spawn(
            Command::new("/bin/sh")
                .args(["-c", "sleep 60 & echo ready; wait"])
                .stdout(Stdio::piped()),
        )?;
        let child = tree.0.as_mut().ok_or("missing leader")?;
        let group = child.id();
        let stdout = child.stdout.take().ok_or("missing output")?;
        let (ready_send, ready) = std::sync::mpsc::channel();
        let (done_send, done) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut output = io::BufReader::new(stdout);
            let mut line = String::new();
            let _ = ready_send.send(output.read_line(&mut line));
            let _ = done_send.send(output.read_to_end(&mut Vec::new()));
        });
        ready.recv_timeout(Duration::from_secs(2))??;
        if timeout {
            let error = tree
                .wait(Duration::from_millis(1))
                .await
                .err()
                .ok_or("watchdog did not time out")?;
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
        drop(tree); // Same guard runs on ? and unwinding before the watchdog returns.
        let ended = done.recv_timeout(Duration::from_secs(2));
        if ended.is_err() {
            // Retire the deliberately leaked descendant when running the red regression.
            Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{group}")])
                .status()?;
        }
        reader.join().map_err(|_| "output reader panicked")?;
        assert!(
            ended.is_ok(),
            "descendant retained output after guard dropped"
        );
        ended??;
    }
    Ok(())
}
