use mongodb::{Client, Database, error::Error};

pub async fn connect_to_db(
    user: & str, password: & str,
    host: & str, port: i32,
    database: & str
) -> Result<Database, Error> {
    let uri = format!(
        "mongodb://{}:{}@{}:{}/{}?retryWrites=true&w=majority",
        user, password, host, port, database
    );
    let client = Client::with_uri_str(uri).await?;
    let db = client.database(database);
    // let collection = db.collection("my_collection");

    Ok(db)
}