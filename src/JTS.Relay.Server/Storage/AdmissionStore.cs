using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;
using Microsoft.Data.Sqlite;

namespace JTS.Relay.Server.Storage;

// Separate from accounting: public identities, edges and opaque enrollment material only.
// All runtime readers share SyncRoot with admission and session creation/revocation.
public sealed partial class AdmissionStore : IDisposable
{
    private readonly SqliteConnection connection;
    private readonly RelayOptions options;
    private readonly TimeProvider clock;
    public object SyncRoot { get; } = new();
    public AdmissionStore(RelayOptions options, TimeProvider clock)
    {
        this.options = options; this.clock = clock;
        var seed = new DeviceRegistry(options).All;
        Directory.CreateDirectory(Path.GetDirectoryName(options.DatabasePath)!);
        connection = new(new SqliteConnectionStringBuilder { DataSource = options.DatabasePath, Pooling = false }.ToString());
        connection.Open();
        try
        {
            Execute(null, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; " +
                "CREATE TABLE IF NOT EXISTS admission_meta(name TEXT PRIMARY KEY,value TEXT NOT NULL); " +
                "CREATE TABLE IF NOT EXISTS admission_devices(id TEXT PRIMARY KEY,spki TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('controller','companion'))); " +
                "CREATE TABLE IF NOT EXISTS admission_peers(controller TEXT NOT NULL REFERENCES admission_devices(id),companion TEXT NOT NULL REFERENCES admission_devices(id),PRIMARY KEY(controller,companion)); " +
                "CREATE TABLE IF NOT EXISTS admission_invitations(id TEXT PRIMARY KEY,controller TEXT NOT NULL REFERENCES admission_devices(id)," +
                "token_hash TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','claimed','bound','cancelled','expired'))," +
                "expires INTEGER NOT NULL,offer TEXT NOT NULL,peer_spki TEXT,response TEXT,signature TEXT,claim_hash TEXT,peer_id TEXT,updated INTEGER NOT NULL); " +
                "CREATE INDEX IF NOT EXISTS admission_invitation_owner ON admission_invitations(controller,state); " +
                "CREATE INDEX IF NOT EXISTS admission_invitation_peer ON admission_invitations(controller,peer_id); " +
                "CREATE TABLE IF NOT EXISTS admission_confirmations(invitation TEXT PRIMARY KEY REFERENCES admission_invitations(id) ON DELETE CASCADE,document TEXT NOT NULL); " +
                "CREATE TABLE IF NOT EXISTS admission_revocations(id TEXT PRIMARY KEY,controller TEXT NOT NULL REFERENCES admission_devices(id),peer TEXT NOT NULL REFERENCES admission_devices(id),request TEXT NOT NULL,controller_spki TEXT NOT NULL,receipt TEXT); " +
                "CREATE INDEX IF NOT EXISTS admission_revocation_peer ON admission_revocations(peer,receipt);");
            using var transaction = connection.BeginTransaction();
            if (Scalar(transaction, "SELECT value FROM admission_meta WHERE name='static_seed_v1'") is null)
            {
                foreach (var device in seed)
                    Execute(transaction, "INSERT INTO admission_devices VALUES($id,$spki,$role)",
                        ("$id", device.Id), ("$spki", Convert.ToBase64String(device.Spki)), ("$role", device.Role));
                foreach (var device in seed.Where(d => d.Role == "controller"))
                foreach (var peer in device.Peers)
                    Execute(transaction, "INSERT INTO admission_peers VALUES($controller,$peer)", ("$controller", device.Id), ("$peer", peer));
                Execute(transaction, "INSERT INTO admission_meta VALUES('static_seed_v1','complete')");
            }
            transaction.Commit();
        }
        catch { connection.Dispose(); throw; }
    }
    public bool TryGet(string id, out AdmittedDevice device)
    {
        lock (SyncRoot)
        {
            using var command = Command(null, "SELECT spki,role FROM admission_devices WHERE id=$id", ("$id", id));
            string encoded, role;
            using (var reader = command.ExecuteReader())
            {
                if (!reader.Read()) { device = null!; return false; }
                encoded = reader.GetString(0); role = reader.GetString(1);
            }
            using var peers = Command(null, role == "controller" ?
                "SELECT companion FROM admission_peers WHERE controller=$id" : "SELECT controller FROM admission_peers WHERE companion=$id", ("$id", id));
            using var rows = peers.ExecuteReader(); var values = new List<string>();
            while (rows.Read()) values.Add(rows.GetString(0));
            device = PublicDeviceIdentity.Parse(id, encoded, role, values); return true;
        }
    }
    // Local operator CLI only. File-system access to this node's DB is the authority;
    // there is deliberately no anonymous controller-registration HTTP endpoint.
    public void AddController(string encoded)
    {
        var bytes = Convert.FromBase64String(encoded);
        var device = PublicDeviceIdentity.Parse(Enrollment.EnrollmentProtocol.Digest(bytes), encoded, "controller", []);
        lock (SyncRoot)
        {
            using var transaction = connection.BeginTransaction();
            AddDevice(transaction, device); transaction.Commit();
        }
    }
    private void AddDevice(SqliteTransaction transaction, AdmittedDevice device)
    {
        using var existing = Command(transaction, "SELECT spki,role FROM admission_devices WHERE id=$id", ("$id", device.Id));
        using (var reader = existing.ExecuteReader())
        {
            if (reader.Read())
            {
                if (reader.GetString(0) != Convert.ToBase64String(device.Spki) || reader.GetString(1) != device.Role)
                    throw new RelayFailure("device_identity_conflict", 409);
                return;
            }
        }
        var count = (long)Scalar(transaction, "SELECT count(*) FROM admission_devices")!;
        var companions = (long)Scalar(transaction, "SELECT count(*) FROM admission_devices WHERE role='companion'")!;
        if (count >= options.MaxDevices || device.Role == "companion" && companions >= options.MaxCompanionDevices)
            throw new RelayFailure("capacity_exhausted", 429);
        Execute(transaction, "INSERT INTO admission_devices VALUES($id,$spki,$role)",
            ("$id", device.Id), ("$spki", Convert.ToBase64String(device.Spki)), ("$role", device.Role));
    }
    private void AddPair(SqliteTransaction transaction, string controller, AdmittedDevice companion)
    {
        if (Scalar(transaction, "SELECT 1 FROM admission_revocations WHERE controller=$controller AND peer=$peer AND receipt IS NULL LIMIT 1",
            ("$controller", controller), ("$peer", companion.Id)) is not null) throw new RelayFailure("revocation_pending", 409);
        AddDevice(transaction, companion);
        var existing = Scalar(transaction, "SELECT 1 FROM admission_peers WHERE controller=$controller AND companion=$peer", ("$controller", controller), ("$peer", companion.Id));
        if (existing is not null) return;
        var maximum = Math.Min(128, options.MaxDevices);
        if ((long)Scalar(transaction, "SELECT count(*) FROM admission_peers WHERE controller=$id", ("$id", controller))! >= maximum ||
            (long)Scalar(transaction, "SELECT count(*) FROM admission_peers WHERE companion=$id", ("$id", companion.Id))! >= maximum)
            throw new RelayFailure("capacity_exhausted", 429);
        Execute(transaction, "INSERT INTO admission_peers VALUES($controller,$peer)", ("$controller", controller), ("$peer", companion.Id));
    }
    private SqliteCommand Command(SqliteTransaction? transaction, string text, params (string Name, object Value)[] parameters)
    {
        var command = connection.CreateCommand(); command.CommandText = text; command.Transaction = transaction;
        foreach (var pair in parameters) command.Parameters.AddWithValue(pair.Name, pair.Value);
        return command;
    }
    private object? Scalar(SqliteTransaction? transaction, string text, params (string Name, object Value)[] parameters)
    { using var command = Command(transaction, text, parameters); return command.ExecuteScalar(); }
    private void Execute(SqliteTransaction? transaction, string text, params (string Name, object Value)[] parameters)
    { using var command = Command(transaction, text, parameters); command.ExecuteNonQuery(); }
    public void Dispose() { lock (SyncRoot) connection.Dispose(); }
}
