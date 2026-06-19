using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MediaBrowser.Controller.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;

namespace Jellyfin.Plugin.PasswordRecovery;

public class PasswordResetFileWatcher : IHostedService, IDisposable
{
    private const string ResetPrefix = "passwordreset";
    private readonly ILogger<PasswordResetFileWatcher> _logger;
    private readonly IServerConfigurationManager _serverConfig;
    private readonly IHttpClientFactory _httpClientFactory;

    private FileSystemWatcher? _watcher;
    private readonly object _dedupLock = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastSentByUsername = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastProcessedByFile = new(StringComparer.OrdinalIgnoreCase);

    public PasswordResetFileWatcher(
        ILogger<PasswordResetFileWatcher> logger,
        IServerConfigurationManager serverConfig,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _serverConfig = serverConfig;
        _httpClientFactory = httpClientFactory;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var config = Plugin.Instance?.Configuration ?? new PluginConfiguration();
        if (!config.Enabled)
        {
            _logger.LogInformation("PasswordRecovery: disabled.");
            return Task.CompletedTask;
        }

        var programDataPath = _serverConfig.ApplicationPaths.ProgramDataPath;
        if (string.IsNullOrWhiteSpace(programDataPath) || !Directory.Exists(programDataPath))
        {
            _logger.LogWarning("PasswordRecovery: ProgramDataPath not found: {Path}", programDataPath);
            return Task.CompletedTask;
        }

        _watcher = new FileSystemWatcher(programDataPath)
        {
            Filter = $"{ResetPrefix}*.json",
            IncludeSubdirectories = false,
            EnableRaisingEvents = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite | NotifyFilters.Size
        };

        _watcher.Created += (_, e) => _ = Task.Run(() => HandleCreatedAsync(e.FullPath));
        _watcher.Renamed += (_, e) => _ = Task.Run(() => HandleCreatedAsync(e.FullPath));
        _watcher.Changed += (_, e) => _ = Task.Run(() => HandleCreatedAsync(e.FullPath));

        _logger.LogInformation("PasswordRecovery: watching {Dir} for {Filter}", programDataPath, _watcher.Filter);
        var existingFiles = Directory.GetFiles(programDataPath, $"{ResetPrefix}*.json", SearchOption.TopDirectoryOnly);
        foreach (var f in existingFiles)
        {
            try
            {
                File.Delete(f);
                _logger.LogInformation("PasswordRecovery: deleted stale reset file {Path}", f);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "PasswordRecovery: could not delete stale reset file {Path}", f);
            }
        }

        _logger.LogInformation("PasswordRecovery: existing reset files cleaned: {Count}", existingFiles.Length);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        Dispose();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        if (_watcher is not null)
        {
            _watcher.EnableRaisingEvents = false;
            _watcher.Dispose();
        }
    }

    private async Task HandleCreatedAsync(string fullPath)
    {
        try
        {
            var config = Plugin.Instance?.Configuration ?? new PluginConfiguration();
            if (!config.Enabled)
            {
                return;
            }

            if (!File.Exists(fullPath))
            {
                return;
            }
            _logger.LogDebug("PasswordRecovery: detected reset file event for {Path}", fullPath);

            // Thread-safe dedup: only one thread passes the 5s window per file.
            var now = DateTimeOffset.UtcNow;
            lock (_dedupLock)
            {
                if (_lastProcessedByFile.TryGetValue(fullPath, out var lastProcessed)
                    && (now - lastProcessed) < TimeSpan.FromSeconds(5))
                {
                    return;
                }
                _lastProcessedByFile[fullPath] = now;
            }

            // Read with retries because Jellyfin may still be writing.
            SerializablePasswordReset? reset = null;
            for (var attempt = 0; attempt < 10; attempt++)
            {
                reset = TryParseResetFile(fullPath);
                if (reset is not null)
                {
                    break;
                }
                await Task.Delay(250).ConfigureAwait(false);
            }

            if (reset is null)
            {
                _logger.LogWarning("PasswordRecovery: could not parse reset file {Path}", fullPath);
                return;
            }

            // Delete the file immediately after successful parse to prevent
            // stale files from blocking future resets. File ownership released
            // once Jellyfin finishes writing (which we verified by parsing OK).
            DeleteFile(fullPath);

            if (reset.ExpirationDate <= DateTime.UtcNow)
            {
                return;
            }

            var username = reset.UserName?.Trim();
            if (string.IsNullOrWhiteSpace(username))
            {
                return;
            }

            var minMinutes = Math.Max(1, config.MinMinutesBetweenEmailsPerUser);
            if (_lastSentByUsername.TryGetValue(username, out var lastSent) && (now - lastSent) < TimeSpan.FromMinutes(minMinutes))
            {
                _logger.LogInformation("PasswordRecovery: throttled email for {User}", username);
                return;
            }

            var (email, wizarrUserId) = await FindWizarrUserEmailAsync(config, username).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(email) || wizarrUserId is null)
            {
                // Do not leak user existence to the client; just log for admin.
                _logger.LogWarning("PasswordRecovery: no Wizarr email found for username {User}", username);
                return;
            }

            var resetLink = await CreateWizarrResetLinkAsync(config, wizarrUserId.Value).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(resetLink))
            {
                _logger.LogWarning("PasswordRecovery: Wizarr reset link generation failed for {User}", username);
                return;
            }

            await SendEmailAsync(config, email, username, resetLink).ConfigureAwait(false);
            _lastSentByUsername[username] = now;

            _logger.LogInformation("PasswordRecovery: reset email sent for {User}", username);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PasswordRecovery: error handling reset file.");
        }
    }

    private SerializablePasswordReset? TryParseResetFile(string fullPath)
    {
        try
        {
            var text = File.ReadAllText(fullPath, Encoding.UTF8).Trim();
            if (string.IsNullOrWhiteSpace(text))
            {
                return null;
            }

            // Workaround for historical bug where an extra '}' could be appended.
            for (var i = 0; i < 2; i++)
            {
                try
                {
                    return JsonSerializer.Deserialize<SerializablePasswordReset>(text);
                }
                catch (JsonException)
                {
                    if (text.EndsWith("}", StringComparison.Ordinal))
                    {
                        text = text[..^1].TrimEnd();
                        continue;
                    }

                    throw;
                }
            }

            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private async Task<(string? Email, int? WizarrUserId)> FindWizarrUserEmailAsync(PluginConfiguration config, string jellyfinUsername)
    {
        if (string.IsNullOrWhiteSpace(config.WizarrBaseUrl) || string.IsNullOrWhiteSpace(config.WizarrApiKey))
        {
            return (null, null);
        }

        if (!Uri.TryCreate(config.WizarrBaseUrl, UriKind.Absolute, out _))
        {
            _logger.LogWarning("PasswordRecovery: invalid WizarrBaseUrl configured: {BaseUrl}", config.WizarrBaseUrl);
            return (null, null);
        }

        try
        {
            using var client = _httpClientFactory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(15);
            client.DefaultRequestHeaders.Add("X-API-Key", config.WizarrApiKey);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var url = $"{config.WizarrBaseUrl.TrimEnd('/')}/api/users";
            using var resp = await client.GetAsync(url).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
                {
                    _logger.LogWarning("PasswordRecovery: Wizarr auth failed (401/403). Check X-API-Key.");
                }
                else
                {
                    _logger.LogWarning("PasswordRecovery: Wizarr users endpoint failed: {Code} {Reason}", (int)resp.StatusCode, resp.ReasonPhrase);
                }

                return (null, null);
            }

            var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (LooksLikeHtml(json))
            {
                _logger.LogWarning("PasswordRecovery: Wizarr users endpoint returned HTML, expected JSON. Check base URL/proxy.");
                return (null, null);
            }

            var users = JsonSerializer.Deserialize<WizarrUsersResponse>(json);
            if (users?.users is null)
            {
                return (null, null);
            }

            foreach (var u in users.users)
            {
                if (u is null)
                {
                    continue;
                }

                if (string.Equals(u.username, jellyfinUsername, StringComparison.OrdinalIgnoreCase))
                {
                    return (u.email, u.id);
                }
            }
        }
        catch (TaskCanceledException)
        {
            _logger.LogWarning("PasswordRecovery: Wizarr users request timed out.");
            return (null, null);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "PasswordRecovery: Wizarr users request failed (server down/unreachable).");
            return (null, null);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "PasswordRecovery: Wizarr users response is not valid JSON.");
            return (null, null);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PasswordRecovery: unexpected error while reading Wizarr users.");
            return (null, null);
        }

        return (null, null);
    }

    private async Task<string?> CreateWizarrResetLinkAsync(PluginConfiguration config, int wizarrUserId)
    {
        try
        {
            using var client = _httpClientFactory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(15);
            client.DefaultRequestHeaders.Add("X-API-Key", config.WizarrApiKey);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var url = $"{config.WizarrBaseUrl.TrimEnd('/')}/api/users/{wizarrUserId}/reset-password";
            using var resp = await client.PostAsync(url, new StringContent("", Encoding.UTF8, "application/json")).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
                {
                    _logger.LogWarning("PasswordRecovery: Wizarr auth failed while creating reset link (401/403).");
                }
                else
                {
                    var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                    _logger.LogWarning(
                        "PasswordRecovery: Wizarr reset link endpoint failed for userId={UserId}: {Code} {Reason}. body={Body}",
                        wizarrUserId,
                        (int)resp.StatusCode,
                        resp.ReasonPhrase,
                        TruncateForLog(body));
                }

                return null;
            }

            var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (LooksLikeHtml(json))
            {
                _logger.LogWarning("PasswordRecovery: Wizarr reset link endpoint returned HTML, expected JSON.");
                return null;
            }

            var link = JsonSerializer.Deserialize<WizarrResetPasswordResponse>(json);
            _logger.LogInformation("PasswordRecovery: Wizarr raw response code='{Code}', message='{Message}', json={Json}",
            link?.code,
            link?.message,
            TruncateForLog(json));
            var resolved = ResolveResetUrl(config.WizarrBaseUrl, link);
            if (string.IsNullOrWhiteSpace(resolved))
            {
                _logger.LogWarning(
                    "PasswordRecovery: Wizarr reset response parsed but no usable link/url for userId={UserId}. body={Body}",
                    wizarrUserId,
                    TruncateForLog(json));
                return null;
            }

            _logger.LogInformation(
                "PasswordRecovery: Wizarr reset link created for userId={UserId}. code={Code} url={Url}",
                wizarrUserId,
                link?.code ?? string.Empty,
                resolved);
            return resolved;
        }
        catch (TaskCanceledException)
        {
            _logger.LogWarning("PasswordRecovery: Wizarr reset link request timed out.");
            return null;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "PasswordRecovery: Wizarr reset link request failed (server down/unreachable).");
            return null;
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "PasswordRecovery: Wizarr reset link response is not valid JSON.");
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PasswordRecovery: unexpected error while creating Wizarr reset link.");
            return null;
        }
    }

    private void DeleteFile(string fullPath)
    {
        try
        {
            File.Delete(fullPath);
            _logger.LogInformation("PasswordRecovery: deleted reset file {Path}", fullPath);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PasswordRecovery: could not delete reset file {Path}", fullPath);
        }
    }

    private Task SendEmailAsync(PluginConfiguration config, string toEmail, string username, string resetLink)
    {
        _logger.LogInformation("PasswordRecovery: SendEmailAsync resetLink = '{ResetLink}'", resetLink);

        if (string.IsNullOrWhiteSpace(config.SmtpHost) || string.IsNullOrWhiteSpace(config.FromEmail))
        {
            throw new InvalidOperationException("SMTP settings are not configured.");
        }

        var subject = config.EmailSubject;
        var body = (config.EmailBodyTemplate ?? string.Empty)
            .Replace("{username}", username, StringComparison.Ordinal)
            .Replace("{reset_link}", resetLink, StringComparison.Ordinal);

        using var message = new MailMessage(config.FromEmail, toEmail, subject, body);
        using var smtp = new SmtpClient(config.SmtpHost, config.SmtpPort)
        {
            EnableSsl = config.SmtpUseSsl
        };

        if (!string.IsNullOrWhiteSpace(config.SmtpUsername))
        {
            smtp.Credentials = new NetworkCredential(config.SmtpUsername, config.SmtpPassword);
        }

        smtp.Send(message);
        return Task.CompletedTask;
    }


    private sealed class SerializablePasswordReset
    {
        public string? Pin { get; set; }
        public string? UserName { get; set; }
        public string? PinFile { get; set; }
        public DateTime ExpirationDate { get; set; }
    }

    private sealed class WizarrUsersResponse
    {
        public WizarrUser[]? users { get; set; }
        public int count { get; set; }
    }

    private sealed class WizarrUser
    {
        public int id { get; set; }
        public string? username { get; set; }
        public string? email { get; set; }
        public string? server { get; set; }
        public string? server_type { get; set; }
        public string? expires { get; set; }
        public string? created { get; set; }
    }

    private sealed class WizarrResetPasswordResponse
    {
        public string? code { get; set; }
        public string? message { get; set; }
    }

    private static bool LooksLikeHtml(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        return body.TrimStart().StartsWith("<", StringComparison.Ordinal);
    }

    private static string? ResolveResetUrl(string baseUrl, WizarrResetPasswordResponse? response)
    {
        
        if (response is null)
            return null;

        var code = response.code?.Trim();
        

        if (string.IsNullOrWhiteSpace(code))
            return null;


        if (Uri.TryCreate(code, UriKind.Absolute, out var abs)
            && (abs.Scheme == Uri.UriSchemeHttp || abs.Scheme == Uri.UriSchemeHttps))
        {
            return abs.ToString();
        }

       
        var cleanBase = baseUrl.TrimEnd('/');
        var cleanCode = code.TrimStart('/');

        return $"{cleanBase}/reset/{cleanCode}";
    }



    private static string TruncateForLog(string? value, int max = 400)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var s = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return s.Length <= max ? s : s[..max] + "...";
    }
}

