using System.Text.Json;

namespace NightOwl.Engines.Execution;

/// <summary>
/// Entry guards for engine-output parsers. Tools under scan control (or a version drift)
/// can emit valid JSON of the wrong shape; the parsers' contract is that such output fails
/// as one clear <see cref="InvalidDataException"/> at the door, or is treated as absent —
/// never as a raw InvalidOperationException from deep inside System.Text.Json.
/// </summary>
internal static class JsonGuards
{
    /// <summary>The document root, or a clear malformed-output error when it is not an object.</summary>
    public static JsonElement RootObject(JsonDocument document, string engine) =>
        document.RootElement.ValueKind == JsonValueKind.Object
            ? document.RootElement
            : throw new InvalidDataException($"{engine} output is malformed: expected a JSON object at the root, got {document.RootElement.ValueKind}.");

    /// <summary>The named array property, or empty when it is missing or not an array.</summary>
    public static IEnumerable<JsonElement> Array(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray()
            : [];

    /// <summary>True for a JSON object — the only kind TryGetProperty is safe on. Array items are not guaranteed to be objects.</summary>
    public static bool IsObject(JsonElement element) => element.ValueKind == JsonValueKind.Object;
}
