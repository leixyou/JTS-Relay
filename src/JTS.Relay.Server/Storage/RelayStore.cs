using Microsoft.Data.Sqlite;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Protocol;

namespace JTS.Relay.Server.Storage;

public sealed class RelayStore : IDisposable
{
    private readonly SqliteConnection connection;
    private readonly object gate = new();
    private readonly RelayOptions options;
    private readonly TimeProvider clock;
    private readonly Action<string> warningSink;

    public RelayStore(RelayOptions options, TimeProvider clock, Action<string>? warningSink = null)
    {
        this.options = options;
        this.clock = clock;
        this.warningSink = warningSink ?? Console.Error.WriteLine;
        Directory.CreateDirectory(Path.GetDirectoryName(options.DatabasePath)!);
        connection = new(new SqliteConnectionStringBuilder { DataSource = options.DatabasePath, Pooling = false }.ToString());
        connection.Open();
        Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; " +
            "CREATE TABLE IF NOT EXISTS presence(device_id TEXT PRIMARY KEY, last_seen INTEGER NOT NULL); " +
            "CREATE TABLE IF NOT EXISTS usage(month TEXT PRIMARY KEY, outbound_bytes INTEGER NOT NULL CHECK(outbound_bytes >= 0)); " +
            "CREATE TABLE IF NOT EXISTS usage_alerts(month TEXT PRIMARY KEY, threshold INTEGER NOT NULL CHECK(threshold IN (0,80,95,100)));");
    }
    public void Touch(string deviceId)
    {
        lock (gate)
            Execute("INSERT INTO presence VALUES($id,$time) ON CONFLICT(device_id) DO UPDATE SET last_seen=excluded.last_seen",
                ("$id", deviceId), ("$time", clock.GetUtcNow().ToUnixTimeSeconds()));
    }
    public DevicePresence[] Presence(IEnumerable<string> deviceIds)
    {
        lock (gate) return deviceIds.Order(StringComparer.Ordinal).Select(id =>
        {
            using var cmd = Command("SELECT last_seen FROM presence WHERE device_id=$id", ("$id", id));
            var value = cmd.ExecuteScalar();
            return new DevicePresence(id, value is long time ? time : null);
        }).ToArray();
    }

    // Reserve before sending: a crash can over-count one chunk but must never under-count/re-open budget.
    public bool TryReserveOutbound(int bytes, string lane)
    {
        if (bytes < 0) throw new ArgumentOutOfRangeException(nameof(bytes));
        lock (gate)
        {
            var month = clock.GetUtcNow().ToString("yyyy-MM", System.Globalization.CultureInfo.InvariantCulture);
            var limit = options.MonthlyOutboundBytes - (lane == "control" ? 0 : options.ControlReserveBytes);
            using var transaction = connection.BeginTransaction();
            using var insert = Command("INSERT OR IGNORE INTO usage VALUES($month,0)", ("$month", month));
            insert.Transaction = transaction;
            insert.ExecuteNonQuery();
            using var update = Command("UPDATE usage SET outbound_bytes=outbound_bytes+$bytes WHERE month=$month AND outbound_bytes <= $limit-$bytes",
                ("$bytes", bytes), ("$month", month), ("$limit", limit));
            update.Transaction = transaction;
            var allowed = update.ExecuteNonQuery() == 1;
            using var query = Command("SELECT outbound_bytes FROM usage WHERE month=$month", ("$month", month));
            query.Transaction = transaction;
            var used = (long)query.ExecuteScalar()!;
            var level = BudgetStatus.Level(used, options.MonthlyOutboundBytes);
            using var mark = Command("INSERT INTO usage_alerts VALUES($month,$level) ON CONFLICT(month) DO UPDATE SET threshold=excluded.threshold WHERE usage_alerts.threshold < excluded.threshold",
                ("$month", month), ("$level", level));
            mark.Transaction = transaction;
            var crossed = mark.ExecuteNonQuery() == 1 && level > 0;
            transaction.Commit();
            // Persist-before-emit avoids duplicate warning storms after restart. A crash
            // between commit and emission may suppress one warning; --status stays exact.
            if (crossed && BudgetStatus.Warning(level) is { } warning) warningSink(warning);
            return allowed;
        }
    }
    public void Cleanup()
    {
        lock (gate)
        {
            var now = clock.GetUtcNow();
            Execute("DELETE FROM presence WHERE last_seen < $cutoff", ("$cutoff", now.AddDays(-options.SecurityRetentionDays).ToUnixTimeSeconds()));
            // A monthly aggregate remains through month-end plus retention. Current month is NEVER deleted.
            Execute("DELETE FROM usage WHERE month <> $current AND date(month || '-01','+1 month') <= date($cutoff)",
                ("$current", now.ToString("yyyy-MM", System.Globalization.CultureInfo.InvariantCulture)),
                ("$cutoff", now.AddDays(-options.UsageRetentionDays).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)));
            Execute("DELETE FROM usage_alerts WHERE month NOT IN (SELECT month FROM usage)");
        }
    }
    private SqliteCommand Command(string text, params (string Name, object Value)[] parameters)
    {
        var cmd = connection.CreateCommand();
        cmd.CommandText = text;
        foreach (var pair in parameters) cmd.Parameters.AddWithValue(pair.Name, pair.Value);
        return cmd;
    }
    private void Execute(string text, params (string Name, object Value)[] parameters)
    {
        using var cmd = Command(text, parameters);
        cmd.ExecuteNonQuery();
    }
    public void Dispose() { lock (gate) connection.Dispose(); }
}
