use migration::runner::run_migrations;
use sea_orm::sqlx::Postgres;
use sea_orm::{ConnectOptions, ConnectionTrait, DbBackend};
use sea_schema::postgres::def::{
    ColumnExpression, ColumnInfo, Schema, StringAttr, TableDef, TimeAttr, Type,
};
use sea_schema::postgres::discovery::SchemaDiscovery;
use similar_asserts::assert_eq;

use crate::fixtures::{Column, ColumnType, DefaultValue, Table};

pub(super) async fn get_pgsql_schema(url: &str) -> Box<dyn super::Schema> {
    let mut url: url::Url = url.parse().unwrap();
    // remove path to connect to cluster
    url.set_path("");

    let conn = sea_orm::Database::connect(url.to_owned()).await.unwrap();
    let db_name: String = ulid::Ulid::new().to_string();
    println!("USING DATABASE {db_name}");
    conn.execute_unprepared(&format!("CREATE DATABASE \"{db_name}\";"))
        .await
        .unwrap();

    url.set_path(&db_name);

    let conn = sea_orm::Database::connect(url.to_owned()).await.unwrap();
    run_migrations(&conn).await.unwrap();

    let pool = ConnectOptions::new(url.to_string())
        .sqlx_pool_options::<Postgres>()
        .connect(url.as_str())
        .await
        .unwrap();

    let schema = SchemaDiscovery::new(pool, "public")
        .discover()
        .await
        .unwrap();
    Box::new(SchemaWrapper(schema))
}

#[derive(Debug)]
struct SchemaWrapper(Schema);

impl super::Schema for SchemaWrapper {
    fn backend(&self) -> DbBackend {
        DbBackend::Postgres
    }

    fn table(&self, name: &str) -> Box<dyn Table> {
        let table = self.0.tables.iter().find(|t| t.info.name == name);
        assert!(table.is_some(), "Table {name} does not exist");
        Box::new(TableWrapper(table.unwrap().to_owned()))
    }
}

#[derive(Clone, Debug)]
struct TableWrapper(TableDef);

impl Table for TableWrapper {
    fn column(&self, name: &str) -> Box<dyn Column> {
        let column = self.0.columns.iter().find(|column| column.name == name);
        assert!(
            column.is_some(),
            "Column {name} does not exist in table {}",
            self.0.info.name
        );
        Box::new(ColumnWrapper {
            info: column.unwrap().to_owned(),
            table: self.0.to_owned(),
        })
    }

    fn columns(&self, columns: &[&str]) -> Box<dyn Table> {
        for column in columns {
            self.column(column);
        }
        for column in &self.0.columns {
            assert!(
                columns.contains(&column.name.as_str()),
                "Unknown column {} exists in table {}",
                column.name,
                self.0.info.name
            );
        }
        Box::new(self.clone())
    }

    fn index(&self, name: &str, unique: bool, columns: &[&str]) -> Box<dyn Table> {
        // PostgreSQL has a limit of 63 characters for index names, so we need to truncate the name
        let name = if name.len() > 63 { &name[..63] } else { name };
        if unique {
            let index = self
                .0
                .unique_constraints
                .iter()
                .find(|index| index.name == name);
            assert!(
                index.is_some(),
                "No unique index with name {name} exists in table {}",
                self.0.info.name
            );
            let index = index.unwrap();

            assert_eq!(
                index.columns.len(),
                columns.len(),
                "Index name {name} in table {}: wrong number of columns",
                self.0.info.name
            );

            for (idx, col) in index.columns.iter().enumerate() {
                assert_eq!(
                    col, columns[idx],
                    "Index name {name} in table {}: wrong column/order",
                    self.0.info.name
                );
            }
        } else {
            // TODO: unclear how to check non-unique indexes with sea-schema
        }

        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
struct ColumnWrapper {
    info: ColumnInfo,
    table: TableDef,
}

impl Column for ColumnWrapper {
    fn r#type(&self, r#type: ColumnType) -> Box<dyn Column> {
        assert_eq!(
            self.info.col_type,
            r#type.into(),
            "Column {} in table {}: invalid type",
            self.info.name,
            self.table.info.name
        );
        Box::new(self.clone())
    }

    fn nullable(&self, nullable: bool) -> Box<dyn Column> {
        assert_eq!(
            self.info.not_null.is_none(),
            nullable,
            "Column {} in table {}: invalid nullability",
            self.info.name,
            self.table.info.name
        );
        Box::new(self.clone())
    }

    fn default(&self, default: Option<DefaultValue>) -> Box<dyn Column> {
        assert_eq!(
            self.info.default,
            default.map(Into::into),
            "Column {} in table {}: invalid default value",
            self.info.name,
            self.table.info.name
        );
        Box::new(self.clone())
    }

    fn primary_key(&self) -> Box<dyn Column> {
        assert!(
            self.table.primary_key_constraints.len() == 1
                && self.table.primary_key_constraints[0]
                    .columns
                    .contains(&self.info.name),
            "Column {} in table {} not a primary key",
            self.info.name,
            self.table.info.name
        );
        Box::new(self.clone())
    }

    fn foreign_key(&self, name: &str, into_table: &str, column: &str) -> Box<dyn Column> {
        let foreign_key = self
            .table
            .reference_constraints
            .iter()
            .find(|foreign_key| foreign_key.columns.contains(&self.info.name));
        assert!(
            foreign_key.is_some(),
            "No foreign key for column {} in table {}",
            self.info.name,
            self.table.info.name
        );
        let foreign_key = foreign_key.unwrap();
        assert_eq!(
            foreign_key.name, name,
            "Column {} in table {}: invalid foreign key name",
            self.info.name, self.table.info.name
        );
        assert_eq!(
            foreign_key.table, into_table,
            "Column {} in table {} not a foreign key referencing table {into_table}",
            self.info.name, self.table.info.name
        );
        assert!(
            foreign_key.foreign_columns.contains(&column.to_string()),
            "Column {} in table {} not a foreign key referencing column {column} in {into_table}",
            self.info.name,
            self.table.info.name
        );
        Box::new(self.clone())
    }
}

impl From<ColumnType> for Type {
    fn from(value: ColumnType) -> Self {
        match value {
            ColumnType::String(length) => Self::Varchar(StringAttr {
                length: length.map(|len| len as u16),
            }),
            ColumnType::Uuid => Self::Char(StringAttr { length: Some(36) }),
            ColumnType::TimestampMilliseconds => {
                Self::TimestampWithTimeZone(TimeAttr { precision: Some(3) })
            }
            ColumnType::TimestampSeconds => {
                Self::TimestampWithTimeZone(TimeAttr { precision: Some(0) })
            }
            ColumnType::Integer => Self::Integer,
            ColumnType::BigInt => Self::BigInt,
            ColumnType::Boolean => Self::Boolean,
            ColumnType::Blob => Self::Bytea,
            ColumnType::Json => Self::Json,
            ColumnType::Text => Self::Text,
            ColumnType::VarBinary(_) => Self::Bytea,
        }
    }
}

impl From<DefaultValue> for ColumnExpression {
    fn from(value: DefaultValue) -> Self {
        match value {
            DefaultValue::String(text) => Self(text),
            DefaultValue::Integer(number) => Self(number.to_string()),
        }
    }
}
