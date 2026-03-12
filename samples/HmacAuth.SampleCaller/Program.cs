using System.Text;
using HmacAuth.HttpClient;

var builder = WebApplication.CreateBuilder(args);

var sampleHost = builder.Configuration.GetSection("SampleHost").Get<SampleHostOptions>()
    ?? throw new InvalidOperationException("SampleHost configuration is missing.");

if (string.IsNullOrWhiteSpace(sampleHost.BaseAddress) ||
    string.IsNullOrWhiteSpace(sampleHost.ClientId) ||
    string.IsNullOrWhiteSpace(sampleHost.Secret))
{
    throw new InvalidOperationException("SampleHost must define BaseAddress, ClientId, and Secret.");
}

builder.Services.AddHttpClient("sample-host", client =>
    {
        client.BaseAddress = new Uri(sampleHost.BaseAddress, UriKind.Absolute);
    })
    .AddHmacSigningHandler(options =>
    {
        options.ClientId = sampleHost.ClientId;
        options.Secret = sampleHost.Secret;
    });

var app = builder.Build();

app.MapGet("/", () => Results.Json(new
{
    name = "HmacAuth.SampleCaller",
    targetBaseAddress = sampleHost.BaseAddress,
    endpoints = new[] { "/call/whoami", "/call/echo" },
}));

app.MapGet("/call/whoami", async (IHttpClientFactory httpClientFactory) =>
{
    using var request = new HttpRequestMessage(HttpMethod.Get, "/secure/whoami");
    return await ForwardAsync(httpClientFactory, request);
});

app.MapPost("/call/echo", async (IHttpClientFactory httpClientFactory, HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var body = await reader.ReadToEndAsync();
    if (string.IsNullOrWhiteSpace(body))
    {
        body = """
               {
                 "message": "hello from the sample caller"
               }
               """;
    }

    var mediaType = string.IsNullOrWhiteSpace(request.ContentType)
        ? "application/json"
        : request.ContentType;

    using var outboundRequest = new HttpRequestMessage(HttpMethod.Post, "/secure/echo")
    {
        Content = new StringContent(body, Encoding.UTF8, mediaType),
    };

    return await ForwardAsync(httpClientFactory, outboundRequest);
});

app.Run();

static async Task<IResult> ForwardAsync(IHttpClientFactory httpClientFactory, HttpRequestMessage request)
{
    using var client = httpClientFactory.CreateClient("sample-host");
    using var response = await client.SendAsync(request);

    var responseBody = await response.Content.ReadAsStringAsync();
    var contentType = response.Content.Headers.ContentType?.ToString() ?? "application/json";

    return Results.Content(responseBody, contentType, Encoding.UTF8, (int)response.StatusCode);
}

internal sealed class SampleHostOptions
{
    public string BaseAddress { get; init; } = string.Empty;

    public string ClientId { get; init; } = string.Empty;

    public string Secret { get; init; } = string.Empty;
}
