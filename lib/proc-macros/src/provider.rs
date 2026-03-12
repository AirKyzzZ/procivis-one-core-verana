use darling::{Error, FromMeta};
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, parse_macro_input};

#[derive(FromMeta)]
struct Attrs {
    skip_capabilities: Option<bool>,
}

pub(crate) fn provider_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let Data::Struct(_) = input.data else {
        return TokenStream::from(
            Error::custom("`Provider` macro can only be applied to a struct.")
                .with_span(&Span::call_site())
                .write_errors(),
        );
    };
    let attribute = input.attrs.iter().find(|a| a.path().is_ident("provider"));
    let capabilities = match attribute {
        None => json_capabilties(),
        Some(attr) => match Attrs::from_meta(&attr.meta) {
            Ok(attrs) => match attrs.skip_capabilities {
                Some(true) => quote!(None),
                _ => json_capabilties(),
            },
            Err(err) => {
                return TokenStream::from(
                    Error::custom(format!(
                        "`Provider` macro failed to parse attributes: {}",
                        err
                    ))
                    .with_span(&attr.span())
                    .write_errors(),
                );
            }
        },
    };

    let struct_name = input.ident;
    TokenStream::from(quote!(impl crate::provider::Provider for #struct_name {
        fn capabilities(&self) -> Option<serde_json::Value> {
            #capabilities
        }

        fn enabled(&self) -> bool {
            true
        }
    }))
}

fn json_capabilties() -> proc_macro2::TokenStream {
    quote!(Some(serde_json::json!(self.get_capabilities())))
}
