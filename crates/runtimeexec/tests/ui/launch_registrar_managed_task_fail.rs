fn bypass(registrar: &mut runtimeexec::LaunchRegistrar<'_>) {
    registrar.register_listener_with_token(|token| {
        let (start, _) =
            diport::ManagedTask::prepare("not-a-listener", diport::DEFAULT_SHUTDOWN_TIMEOUT);
        start
            .spawn(token, |managed_token| async move {
                managed_token.cancelled().await;
                Ok(())
            })
            .into_registration()
    });
}

fn main() {}
