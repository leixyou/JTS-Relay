using System.Globalization;
using JTS.Relay.Server.Configuration;
using Microsoft.Data.Sqlite;

namespace JTS.Relay.Server.Storage;

/// <summary>Local operator query: never starts listeners, migrates a database, or returns identities.</summary>
public static class BudgetStatusReader
{
    public static BudgetStatus Read(RelayOptions options, TimeProvider clock)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = options.DatabasePath, Mode = SqliteOpenMode.ReadOnly, Pooling = false, DefaultTimeout = 5
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        var month = clock.GetUtcNow().ToString("yyyy-MM", CultureInfo.InvariantCulture);
        command.CommandText = "SELECT outbound_bytes FROM usage WHERE month=$month";
        command.Parameters.AddWithValue("$month", month);
        var bytes = command.ExecuteScalar() as long? ?? 0;
        return BudgetStatus.Create(month, bytes, options);
    }
}
