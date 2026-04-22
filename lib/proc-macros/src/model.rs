use darling::util::Flag;
use darling::{Error, FromAttributes};
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{Field, Fields, FieldsNamed, ItemStruct};

pub(super) fn repository_model(input: TokenStream) -> TokenStream {
    if let Ok(struct_item) = syn::parse::<ItemStruct>(input) {
        match process_model_struct(struct_item) {
            Ok(field) => field,
            Err(err) => TokenStream::from(err.with_span(&Span::call_site()).write_errors()),
        }
    } else {
        TokenStream::from(
            Error::custom("`Model` macro can only be applied to a struct.")
                .with_span(&Span::call_site())
                .write_errors(),
        )
    }
}

struct IdentifierField {
    field_name: proc_macro2::Ident,
    field_type: syn::Type,
}

fn process_model_struct(struct_item: ItemStruct) -> Result<TokenStream, Error> {
    if struct_item
        .attrs
        .iter()
        .any(|attr| attr.path().is_ident("model"))
    {
        return Err(Error::custom(
            "#[model] attributes not allowed on struct level",
        ));
    }

    let identifier_field = match struct_item.fields {
        Fields::Named(named_fields) => extract_identifier_from_fields(named_fields)?,
        Fields::Unnamed(_) | Fields::Unit => {
            return Err(Error::custom(
                "`Model` macro only usable on structs with named fields",
            ));
        }
    };

    let struct_name = struct_item.ident;
    let IdentifierField {
        field_name,
        field_type,
    } = identifier_field;

    Ok(quote! {
        impl crate::model::relation::Model for #struct_name {
            type Id = #field_type;
            fn id(&self) -> &Self::Id {
                &self.#field_name
            }
        }
    }
    .into())
}

fn extract_identifier_from_fields(fields: FieldsNamed) -> Result<IdentifierField, Error> {
    let mut identifier_field: Option<IdentifierField> = None;

    for field in fields.named {
        if let Some(extracted) = extract_identifier_from_field(field)? {
            if identifier_field.is_some() {
                return Err(Error::custom("Multiple model identifier fields specified"));
            }

            identifier_field = Some(extracted);
        }
    }

    match identifier_field {
        Some(field) => Ok(field),
        None => Err(Error::custom(
            "No model identifier field specified. Mark the identifier field with `#[model(id)]`.",
        )),
    }
}

#[derive(FromAttributes)]
#[darling(attributes(model))]
struct ModelAttributes {
    id: Flag,
}

fn extract_identifier_from_field(field: Field) -> Result<Option<IdentifierField>, Error> {
    let attributes = ModelAttributes::from_attributes(&field.attrs)?;
    if !attributes.id.is_present() {
        return Ok(None);
    }

    let field_name = field
        .ident
        .ok_or(Error::custom("Could not extract field name"))?;

    Ok(Some(IdentifierField {
        field_name,
        field_type: field.ty,
    }))
}
