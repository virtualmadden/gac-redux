//! `gac list`: the accounts and roles from the inventory.

use std::fmt::Write as _;

use serde::Serialize;

use crate::cli::ListArgs;
use crate::cli::context::Context;
use crate::error::{Error, Result};
use crate::portal::Account;
use crate::ui;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Listing<'a> {
    session: &'a str,
    fetched_at: String,
    accounts: &'a [Account],
}

pub async fn run(ctx: &Context, args: ListArgs) -> Result<()> {
    let files = ctx.files().await?;
    let session = ctx.resolve_session(&files, None)?;
    let snapshot = ctx.accounts(&session, args.refresh).await?;
    let text = if args.json {
        let listing = Listing {
            session: session.cache_key(),
            fetched_at: snapshot.fetched_at.to_string(),
            accounts: &snapshot.items,
        };
        let mut json =
            serde_json::to_string_pretty(&listing).expect("serializing plain data cannot fail");
        json.push('\n');
        json
    } else {
        table(&snapshot.items)
    };
    ui::output(text).map_err(|err| Error::io("could not write to stdout", err))
}

fn table(accounts: &[Account]) -> String {
    let rows: Vec<[&str; 3]> = accounts
        .iter()
        .flat_map(|a| {
            a.roles
                .iter()
                .map(move |r| [a.id.as_str(), a.name.as_str(), r.as_str()])
        })
        .collect();
    let header = ["ACCOUNT ID", "ACCOUNT NAME", "ROLE"];
    let width = |col: usize| {
        rows.iter()
            .map(|row| row[col].chars().count())
            .chain([header[col].len()])
            .max()
            .unwrap_or_default()
    };
    let (w0, w1) = (width(0), width(1));
    let mut out = String::new();
    for row in std::iter::once(header).chain(rows.iter().copied()) {
        let _ = writeln!(out, "{:<w0$}  {:<w1$}  {}", row[0], row[1], row[2]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligns_columns() {
        let accounts = [Account {
            id: "111122223333".parse().unwrap(),
            name: "payments-prod".into(),
            email: None,
            roles: vec![
                "AdministratorAccess".parse().unwrap(),
                "ReadOnly".parse().unwrap(),
            ],
        }];
        insta::assert_snapshot!(table(&accounts), @r"
        ACCOUNT ID    ACCOUNT NAME   ROLE
        111122223333  payments-prod  AdministratorAccess
        111122223333  payments-prod  ReadOnly
        ");
    }
}
