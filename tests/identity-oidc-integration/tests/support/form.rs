use html5ever::tokenizer::{BufferQueue,StartTag,Token,TokenSink,TokenSinkResult,Tokenizer};
use std::cell::RefCell;
#[derive(Default)]
struct LoginForm(RefCell<Option<String>>);
impl TokenSink for LoginForm {
    type Handle = ();
    fn process_token(&self, token:Token, _:u64) -> TokenSinkResult<()> {
        if let Token::TagToken(tag) = token
            && tag.kind == StartTag && tag.name.as_ref() == "form"
            && tag.attrs.iter().any(|a| a.name.local.as_ref()=="id" && a.value.as_ref()=="kc-form-login")
            && let Some(action) = tag.attrs.iter().find(|a| a.name.local.as_ref()=="action")
        {
            self.0.replace(Some(action.value.to_string()));
        }
        TokenSinkResult::Continue
    }
}
pub fn action(html:&str) -> anyhow::Result<String> {
    let input = BufferQueue::default();
    input.push_back(html.into());
    let parser = Tokenizer::new(LoginForm::default(), Default::default());
    let _ = parser.feed(&input);
    parser.end();
    parser.sink.0.into_inner().ok_or_else(||anyhow::anyhow!("Keycloak login form missing"))
}
