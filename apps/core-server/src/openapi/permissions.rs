use utoipa::Modify;
use utoipa::openapi::path::Operation;

/// Modifies description of endpoints, adding declared permissions
pub struct PermissionsModifier;

impl Modify for PermissionsModifier {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        for (_, item) in openapi.paths.paths.as_mut_slice() {
            for operation in [
                item.get.as_mut(),
                item.put.as_mut(),
                item.post.as_mut(),
                item.delete.as_mut(),
                item.patch.as_mut(),
            ]
            .into_iter()
            .flatten()
            {
                modify_operation(operation);
            }
        }
    }
}

fn modify_operation(operation: &mut Operation) {
    let Some(permissions) = operation
        .extensions
        .as_ref()
        .and_then(|e| e.get("x-permissions"))
        .and_then(|v| v.as_array())
        .map(|vals| {
            vals.iter()
                .filter_map(|v| v.as_str())
                .map(|v| format!("<code>{v}</code>"))
                .collect::<Vec<_>>()
        })
    else {
        return;
    };

    if permissions.is_empty() {
        return;
    }

    let declaration = format!("<strong>Permissions:</strong> {}", permissions.join(" "));

    match operation.description.as_mut() {
        Some(description) => {
            description.insert_str(0, &format!("{declaration}\n\n"));
        }
        None => {
            operation.description = Some(declaration);
        }
    };
}
