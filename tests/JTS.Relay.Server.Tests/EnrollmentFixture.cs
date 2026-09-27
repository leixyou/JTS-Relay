using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Enrollment;
using JTS.Relay.Server.Forwarding;
using JTS.Relay.Server.Security;
using JTS.Relay.Server.Storage;

namespace JTS.Relay.Server.Tests;

internal sealed class EnrollmentFixture : IDisposable
{
    private readonly string directory = Directory.CreateTempSubdirectory("jts-enrollment-").FullName;
    public TestIdentity Controller { get; } = new();
    public TestIdentity OtherController { get; } = new();
    public TestIdentity Companion { get; } = new();
    public TestClock Clock { get; } = new();
    public RelayOptions Options { get; }
    public AdmissionStore Store { get; private set; } = null!;
    public DeviceRegistry Registry { get; private set; } = null!;
    public SessionCoordinator Sessions { get; private set; } = null!;
    public EnrollmentService Service { get; private set; } = null!;
    public EnrollmentFixture(Action<RelayOptions>? configure = null)
    {
        Options = new() { PublicOrigin = TestIdentity.Origin, DatabasePath = Path.Combine(directory, "relay.sqlite"),
            Devices = [Controller.Options("controller"), OtherController.Options("controller")] };
        configure?.Invoke(Options); Reopen();
    }
    public void Reopen()
    {
        Sessions?.Dispose(); Store?.Dispose();
        Store = new(Options, Clock); Registry = new(Options, Store);
        Sessions = new(Options, Registry, Clock); Service = new(Store, Registry, Sessions);
    }
    public (EnrollmentView View, string Token, object Request) Create(TestIdentity? controller = null, byte[]? offer = null)
    {
        var token = RandomNumberGenerator.GetBytes(32);
        var request = new { action = "create", invitationId = Guid.NewGuid().ToString("D"),
            claimTokenHash = EnrollmentProtocol.Digest(token), offerBase64 = Convert.ToBase64String(offer ?? RandomNumberGenerator.GetBytes(64)),
            expiresAtUnixSeconds = Clock.Now.AddMinutes(10).ToUnixTimeSeconds() };
        return ((EnrollmentView)Execute(request, controller), Convert.ToBase64String(token), request);
    }
    public object Execute(object request, TestIdentity? identity = null) => Service.Execute((identity ?? Controller).Id, Json(request));
    public EnrollmentView Public(object request, bool claim = false) => Service.Public(Json(request), claim);
    public static JsonElement Json(object value) => JsonSerializer.SerializeToElement(value, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    public static object Claim(EnrollmentView invitation, string token, TestIdentity peer, byte[]? response = null, TestIdentity? signer = null)
    {
        var responseBase64 = Convert.ToBase64String(response ?? RandomNumberGenerator.GetBytes(48));
        var peerSPKIBase64 = peer.Options("companion").PublicKeySpkiBase64;
        var transcript = EnrollmentProtocol.Transcript(invitation.InvitationId, invitation.ControllerDeviceId,
            invitation.OfferBase64, responseBase64, peerSPKIBase64);
        return new { invitationId = invitation.InvitationId, claimTokenBase64 = token, peerSPKIBase64, responseBase64,
            signatureBase64 = Convert.ToBase64String((signer ?? peer).Key.SignData(Encoding.UTF8.GetBytes(transcript),
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) };
    }
    public EnrollmentView Bind((EnrollmentView View, string Token, object Request) invite, TestIdentity? controller = null)
    {
        var claim = Public(Claim(invite.View, invite.Token, Companion), true);
        return (EnrollmentView)Execute(ConfirmationRequest(claim, controller), controller);
    }
    public object ConfirmationRequest(EnrollmentView claim, TestIdentity? controller = null) => new
    {
        action = "confirm", invitationId = claim.InvitationId, claimHash = claim.Claim!.ClaimHash,
        confirmation = claim.Confirmation ?? (controller ?? Controller).Confirm(claim, Clock.Now.ToUnixTimeSeconds())
    };
    public void Dispose()
    {
        Sessions.Dispose(); Store.Dispose(); Controller.Dispose(); OtherController.Dispose(); Companion.Dispose();
        Directory.Delete(directory, true);
    }
}
