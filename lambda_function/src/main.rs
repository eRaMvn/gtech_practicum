use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::{json, Value};
mod events;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let func = service_fn(lambda_handler);
    lambda_runtime::run(func).await?;
    Ok(())
}

async fn lambda_handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    let (event, _context) = event.into_parts();
    let event_name = event["detail"]["eventName"]
        .as_str()
        .expect("no event info");

    Ok(json!({ "message": format!("Hello, {}!", event_name) }))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_my_lambda_handler() {
        let input =
            serde_json::from_str(events::ATTACH_ROLE_POLICY_EVENT).expect("failed to parse event");
        let context = lambda_runtime::Context::default();

        let event = lambda_runtime::LambdaEvent::new(input, context);

        let response = lambda_handler(event).await.expect("something");
        assert_eq!(
            *response.get("message").unwrap(),
            "Hello, AttachRolePolicy!"
        )
    }
}
