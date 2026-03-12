use darling::Error;
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{ItemTrait, TraitItem, TypeParamBound};

pub(super) fn provider_mock(input: TokenStream) -> TokenStream {
    let Ok(input) = syn::parse::<ItemTrait>(input) else {
        return TokenStream::from(
            Error::custom("`ProviderMock` macro can only be applied to a trait.")
                .with_span(&Span::call_site())
                .write_errors(),
        );
    };
    if !input.supertraits.iter().any(|st| {
        let TypeParamBound::Trait(trait_bound) = st else {
            return false;
        };
        trait_bound.path.is_ident("Provider")
    }) {
        return TokenStream::from(
            Error::custom(format!("`ProviderMock` macro can only be applied to a trait with `Provider` as supertrait. {:?}", input.supertraits))
                .with_span(&Span::call_site())
                .write_errors(),
        );
    };

    let mut trait_fns = vec![];
    for item in &input.items {
        let TraitItem::Fn(fn_item) = item else {
            continue;
        };
        trait_fns.push(fn_item);
    }
    let trait_name = &input.ident;
    let trait_attrs = &input.attrs;
    quote!(
        #[cfg(any(test, feature = "mock"))]
        mockall::mock! {
            pub #trait_name {}

            impl crate::provider::Provider for #trait_name {
                fn capabilities(&self) -> Option<serde_json::Value>;
                fn enabled(&self) -> bool;
            }

            #(#trait_attrs)*
            impl #trait_name for #trait_name {
                #(#trait_fns)*
            }
        }

        #input
    )
    .into()
}
