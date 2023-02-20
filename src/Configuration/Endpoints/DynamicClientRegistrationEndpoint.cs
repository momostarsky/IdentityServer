using System.Text.Json;
using System.Text.Json.Serialization;
using Duende.IdentityServer.Configuration.Models.DynamicClientRegistration;
using Duende.IdentityServer.Configuration.Validation.DynamicClientRegistration;
using Duende.IdentityServer.Models;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Duende.IdentityServer.Configuration;

public class DynamicClientRegistrationEndpoint
{
    private readonly IDynamicClientRegistrationValidator _validator;
    private readonly ICustomDynamicClientRegistrationValidator _customValidator;
    private readonly IClientConfigurationStore _store;
    private readonly ILogger<DynamicClientRegistrationEndpoint> _logger;

    public DynamicClientRegistrationEndpoint(
        IDynamicClientRegistrationValidator validator,
        ICustomDynamicClientRegistrationValidator customValidator,
        IClientConfigurationStore store,
        ILogger<DynamicClientRegistrationEndpoint> logger)
    {
        _validator = validator;
        _customValidator = customValidator;
        _store = store;
        _logger = logger;
    }

    public async Task Process(HttpContext context)
    {
        // Check content type
        if (!HasCorrectContentType(context.Request))
        {
            WriteContentTypeError(context.Response);
            return;
        }

        // Parse body
        var document = await TryParseAsync(context.Request);
        if(document == null)
        {
            await WriteBadRequestError(context.Response);
            return;
        }

        // Validate request values 
        var result = await ValidateAsync(context, document);

        if (result is DynamicClientRegistrationValidationError validationError)
        {
            await WriteValidationError(validationError, context);
        }
        else if (result is DynamicClientRegistrationValidatedRequest validatedRequest)
        {
            var response = await CreateAndPersistClientWithSecret(validatedRequest);
            await WriteSuccessResponse(context, response);
        }
    }

    private async Task<DynamicClientRegistrationValidationResult> ValidateAsync(HttpContext context, DynamicClientRegistrationRequest request)
    {
        // validate body values and construct Client object
        var result = await _validator.ValidateAsync(context.User, request);

        if (result is DynamicClientRegistrationValidationError errorResult)
        {
            return errorResult;
        }
        else if (result is DynamicClientRegistrationValidatedRequest validatedRequest)
        {
            return await _customValidator.ValidateAsync(context.User, validatedRequest);
        } 
        else 
        {
            throw new Exception("Can't happen");
        }
    }

    private static bool HasCorrectContentType(HttpRequest request) => 
        // REVIEW: HasJsonContentType accepts content types like application/ld+json
        // (really, anything in the form application/*-json). The spec technically only allows application/json for DCR.
        // Do we care?
        request.HasJsonContentType();

    private void WriteContentTypeError(HttpResponse response)
    {
        _logger.LogWarning("Invalid content type in dynamic client registration request");
        response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
    }

    private async Task<DynamicClientRegistrationRequest?> TryParseAsync(HttpRequest request)
    {
        try
        {
            var document = await request.ReadFromJsonAsync<DynamicClientRegistrationRequest>();
            if(document == null) 
            {
                _logger.LogWarning("Dynamic client registration request body cannot be null");
            }
            return document;
        } 
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse dynamic client registration request body");
            return default;
        }
    }

    private async Task WriteBadRequestError(HttpResponse response)
    {
        response.StatusCode = StatusCodes.Status400BadRequest;
        await response.WriteAsJsonAsync(new DynamicClientRegistrationErrorResponse
        {
            Error = DynamicClientRegistrationErrors.InvalidClientMetadata,
            ErrorDescription = "malformed metadata document"
        });
    }

    public virtual async Task WriteValidationError(DynamicClientRegistrationValidationError error, HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new DynamicClientRegistrationErrorResponse
        {
            Error = error.Error,
            ErrorDescription = error.ErrorDescription
        });
    }

    // Review: Should we extract this into a service in DI?
    public virtual Task<(Secret secret, string plainText)> GenerateSecret()
    {
        var plainText = CryptoRandom.CreateUniqueId();

        // TODO should there be a default lifetime on the secret?
        var secret = new Secret(plainText.ToSha256());

        return Task.FromResult((secret, plainText));
    }

    public virtual async Task<DynamicClientRegistrationResponse> CreateAndPersistClientWithSecret(DynamicClientRegistrationValidatedRequest validatedRequest)
    {
        var secretPlainText = await AddClientSecret(validatedRequest);

        // create client in configuration system
        await _store.AddAsync(validatedRequest.Client);

        return (DynamicClientRegistrationResponse) validatedRequest.Original with
        {
            ClientId = validatedRequest.Client.ClientId,
            ClientSecret = secretPlainText,
            ClientSecretExpiresAt = DateTimeOffset.MaxValue.ToUnixTimeSeconds(),
        };
    }

    public virtual async Task WriteSuccessResponse(HttpContext context, DynamicClientRegistrationResponse response)
    {
        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        context.Response.StatusCode = StatusCodes.Status201Created;
        await context.Response.WriteAsJsonAsync(response, options);
    }

    public virtual async Task<string> AddClientSecret(DynamicClientRegistrationValidatedRequest validatedRequest)
    {
        if (validatedRequest.Client.ClientSecrets.Any())
        {
            // TODO - Error message
            throw new Exception("Validator cannot set secrets on the client because we need the plaintext of the secret outside the validator");
        }

        var (secret, plainText) = await GenerateSecret();
        validatedRequest.Client.ClientSecrets.Add(secret);
        return plainText;
    }
}