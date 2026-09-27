using System.Text.Json;
using JTS.Relay.Server.Enrollment;
using JTS.Relay.Server.Protocol;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class RevocationTests
{
    private static RevocationRequest Request(EnrollmentFixture f, TestIdentity? controller = null)
    {
        controller ??= f.Controller;
        var request = new RevocationRequest(2, Guid.NewGuid().ToString("D"), TestIdentity.Origin, controller.Id,
            f.Companion.Id, Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"), f.Clock.Now.ToUnixTimeSeconds(), "");
        return request with { SignatureBase64 = controller.SignText(request.Transcript()) };
    }
    private static RevocationReceipt Receipt(EnrollmentFixture f, RevocationRequest request)
    {
        var receipt = new RevocationReceipt(2, request.RevocationId, request.RequestHash, request.ControllerDeviceId,
            request.PeerDeviceId, f.Clock.Now.ToUnixTimeSeconds(), "");
        return receipt with { SignatureBase64 = f.Companion.SignText(receipt.Transcript()) };
    }
    private static object Execute(EnrollmentFixture f, TestIdentity identity, object payload) =>
        new RevocationService(f.Store, f.Registry, f.Sessions).Execute(identity.Id, EnrollmentFixture.Json(payload));
    [Fact]
    public void SubmitCutsTicketsButOnlySignedEndpointReceiptCompletesAndRetryCannotCutNewBinding()
    {
        using var f = new EnrollmentFixture(); f.Bind(f.Create()); f.Bind(f.Create(f.OtherController), f.OtherController);
        var session = f.Sessions.Create(f.Registry.Get(f.Controller.Id), new(f.Companion.Id, "control"));
        var active = f.Sessions.Claim(session.Ticket).Session;
        var ticket = f.Sessions.Create(f.Registry.Get(f.Controller.Id), new(f.Companion.Id, "file"));
        var request = Request(f);
        var view = (RevocationView)Execute(f, f.Controller, new { action = "submit", revocation = request });
        Assert.Equal("pending", view.State); Assert.Null(view.Receipt); Assert.True(active.IsComplete);
        Assert.Throws<RelayFailure>(() => f.Sessions.Claim(ticket.Ticket));
        Assert.False(f.Registry.AuthorizesPair(f.Controller.Id, f.Companion.Id));
        Assert.True(f.Registry.AuthorizesPair(f.OtherController.Id, f.Companion.Id));
        Assert.Empty(f.Sessions.Poll(f.Registry.Get(f.Companion.Id)));
        Assert.Equal(view, Assert.Single(f.Store.PollRevocations(f.Registry.Get(f.Companion.Id))));
        f.Reopen();
        Assert.Equal(view, Execute(f, f.Controller, new { action = "submit", revocation = request }));
        Assert.Throws<RelayFailure>(() => f.Bind(f.Create()));
        f.Clock.Now = f.Clock.Now.AddSeconds(-10); // Endpoint and controller clocks need not agree.
        var receipt = Receipt(f, request);
        var complete = (RevocationView)Execute(f, f.Companion, new { action = "complete", receipt });
        Assert.Equal("complete", complete.State); Assert.Equal(receipt, complete.Receipt);
        Assert.Empty(f.Store.PollRevocations(f.Registry.Get(f.Companion.Id)));
        f.Reopen(); Assert.Equal(complete, Execute(f, f.Companion, new { action = "complete", receipt }));
        f.Bind(f.Create());
        Assert.Equal(complete, Execute(f, f.Controller, new { action = "submit", revocation = request }));
        Assert.True(f.Registry.AuthorizesPair(f.Controller.Id, f.Companion.Id));
    }
    [Fact]
    public void WrongOwnerAudienceChangedRequestOrForgedReceiptFailsClosed()
    {
        using var f = new EnrollmentFixture(); f.Bind(f.Create()); var request = Request(f);
        foreach (var bad in new[] { request with { RelayOrigin = "https://wrong.example" },
            request with { SignatureBase64 = f.OtherController.SignText(request.Transcript()) } })
            Assert.Throws<RelayFailure>(() => Execute(f, f.Controller, new { action = "submit", revocation = bad }));
        Assert.Throws<RelayFailure>(() => Execute(f, f.OtherController, new { action = "submit", revocation = request }));
        Assert.Throws<RelayFailure>(() => Execute(f, f.OtherController, new { action = "submit", revocation = Request(f, f.OtherController) }));
        var pending = Execute(f, f.Controller, new { action = "submit", revocation = request });
        var changed = request with { GrantId = Guid.NewGuid().ToString("D") };
        changed = changed with { SignatureBase64 = f.Controller.SignText(changed.Transcript()) };
        Assert.Equal(409, Assert.Throws<RelayFailure>(() => Execute(f, f.Controller, new { action = "submit", revocation = changed })).Status);
        Assert.Equal(404, Assert.Throws<RelayFailure>(() => Execute(f, f.OtherController, new { action = "status", revocationId = request.RevocationId })).Status);
        var receipt = Receipt(f, request);
        foreach (var bad in new[] { receipt with { RequestHash = new string('0',64) },
            receipt with { SignatureBase64 = f.Controller.SignText(receipt.Transcript()) } })
            Assert.Throws<RelayFailure>(() => Execute(f, f.Companion, new { action = "complete", receipt = bad }));
        Assert.Equal(pending, Execute(f, f.Controller, new { action = "status", revocationId = request.RevocationId }));
    }
    [Fact]
    public void MailboxPollAndPersistentStorageAreBounded()
    {
        using var f = new EnrollmentFixture(o => { o.MaxStoredEnrollments = 33; }); f.Bind(f.Create());
        for (var i = 0; i < 33; i++) Execute(f, f.Controller, new { action = "submit", revocation = Request(f) });
        var poll = Execute(f, f.Companion, new { action = "poll" });
        var json = EnrollmentFixture.Json(poll);
        Assert.Equal(32, json.GetProperty("revocations").GetArrayLength());
        Assert.True(JsonSerializer.SerializeToUtf8Bytes(poll).Length <= 65536);
        Assert.Equal(429, Assert.Throws<RelayFailure>(() => Execute(f, f.Controller, new { action = "submit", revocation = Request(f) })).Status);
        f.Clock.Now = f.Clock.Now.AddDays(365); f.Reopen();
        Assert.Equal(32, f.Store.PollRevocations(f.Registry.Get(f.Companion.Id)).Length);
    }
}
