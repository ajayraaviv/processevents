// See https://aka.ms/new-console-template for more information
using Azure.Identity;
using Azure.Messaging.EventHubs.Consumer;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using System.Net;

// Add the required using directive for Microsoft.Extensions.Configuration.Json
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

internal class Program
{
    private static async Task Main(string[] args)
    {
        Console.WriteLine("Hello, World!");

        // Build configuration to read from appsettings.json
        IConfiguration configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        // Get the Key Vault name from appsettings.json
        string keyVaultName = configuration["KeyVaultName"];
        if (string.IsNullOrEmpty(keyVaultName))
        {
            Console.WriteLine("KeyVaultName is not configured in appsettings.json.");
            return;
        }

        // Get Event Hub configuration from appsettings.json
        string eventHubNamespace = configuration["EventHub:Namespace"];
        string eventHubName = configuration["EventHub:Name"];
        string consumerGroup = configuration["EventHub:ConsumerGroup"];

        if (string.IsNullOrEmpty(eventHubNamespace) || string.IsNullOrEmpty(eventHubName) || string.IsNullOrEmpty(consumerGroup))
        {
            Console.WriteLine("Event Hub configuration is missing in appsettings.json.");
            return;
        }

        // Start reading messages from the Event Hub
        await ReadFromEventHub(eventHubNamespace, eventHubName, consumerGroup, keyVaultName);
    }

    private static async Task ReadFromEventHub(string eventHubNamespace, string eventHubName, string consumerGroup, string keyVaultName)
    {
        // Authenticate using DefaultAzureCredential
        var options = new DefaultAzureCredentialOptions
        {
            Diagnostics =
            {
                IsLoggingContentEnabled = true,
                IsAccountIdentifierLoggingEnabled = true
            }
        };

        var credential = new DefaultAzureCredential(options);

        // Create an Event Hub consumer client using Azure RBAC
        await using var consumerClient = new EventHubConsumerClient(consumerGroup, eventHubNamespace, eventHubName, credential);

        Console.WriteLine("Listening for messages from Event Hub...");

        try
        {
            await foreach (PartitionEvent partitionEvent in consumerClient.ReadEventsAsync())
            {
                string eventData = partitionEvent.Data.EventBody.ToString();
                Console.WriteLine($"Received event: {eventData}");
                

                // Deserialize the event data into an EventItem
                EventItem eventItem = JsonSerializer.Deserialize<SubscribedEvents>(eventData).Value[0];

                if (eventItem != null && eventItem.SubscriptionId != null && eventItem.SubscriptionId != "NA")
                {
                    // Pass the EventItem to the InspectEventData method
                    InspectEventData(eventItem, keyVaultName);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred while reading from Event Hub: {ex.Message}");
        }
    }

    private static void InspectEventData(EventItem eventItem, string keyVaultName)
    {
        // Construct the Key Vault URL
        string keyVaultUrl = $"https://{keyVaultName}.vault.azure.net/";

        // Parse the EncryptionCertificateId to extract the key ID
        string keyId = eventItem.EncryptedContent.EncryptionCertificateId;

        // Construct the secret ID for the private key
        string secretId = keyId.Replace("/keys/", "/secrets/");

        // Parse the secretId to extract the secret name and version
        Uri secretUri = new Uri(secretId);
        string[] segments = secretUri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (segments.Length < 3 || segments[0] != "secrets")
        {
            Console.WriteLine("Invalid SecretId format.");
            return;
        }

        string secretName = segments[1];
        string secretVersion = segments[2];

        // Authenticate using DefaultAzureCredential (supports Managed Identity, Visual Studio, etc.)
        var credential = new DefaultAzureCredential();

        // Create a SecretClient to interact with Key Vault
        var secretClient = new SecretClient(new Uri(keyVaultUrl), credential); 

        // Retrieve the private key as a secret from Key Vault
        KeyVaultSecret privateKeySecret = secretClient.GetSecret(secretName, secretVersion);

        // Convert the private key (Base64-encoded) into an X509Certificate2 instance
        byte[] privateKeyBytes = Convert.FromBase64String(privateKeySecret.Value);
        X509Certificate2 x509Certificate = new X509Certificate2(privateKeyBytes);

        // Extract the RSA private key from the X509Certificate2 instance
        RSA rsa = x509Certificate.GetRSAPrivateKey();

        // Decrypt the symmetric key using the RSA private key
        byte[] encryptedSymmetricKey = Convert.FromBase64String(eventItem.EncryptedContent.DataKey);
        byte[] decryptedSymmetricKey = rsa.Decrypt(encryptedSymmetricKey, RSAEncryptionPadding.OaepSHA1);

        // Decode the encrypted payload and the provided signature from Base64
        byte[] encryptedPayload = Convert.FromBase64String(eventItem.EncryptedContent.Data);
        byte[] expectedSignature = Convert.FromBase64String(eventItem.EncryptedContent.DataSignature);

        // Compute the HMAC-SHA256 signature of the encrypted payload
        byte[] actualSignature;
        using (HMACSHA256 hmac = new HMACSHA256(decryptedSymmetricKey))
        {
            actualSignature = hmac.ComputeHash(encryptedPayload);
        }

        // Compare the computed signature with the provided signature
        if (actualSignature.SequenceEqual(expectedSignature))
        {
            Console.WriteLine("Signature verification succeeded. Proceeding with payload decryption...");

            // Create an AES provider for decryption
            Aes aesProvider = Aes.Create();
            aesProvider.Key = decryptedSymmetricKey;
            aesProvider.Padding = PaddingMode.PKCS7;
            aesProvider.Mode = CipherMode.CBC;

            // Obtain the initialization vector (IV) from the symmetric key itself
            int vectorSize = 16;
            byte[] iv = new byte[vectorSize];
            Array.Copy(decryptedSymmetricKey, iv, vectorSize);
            aesProvider.IV = iv;

            // Decrypt the resource data content
            string decryptedResourceData;
            using (var decryptor = aesProvider.CreateDecryptor())
            {
                using (MemoryStream msDecrypt = new MemoryStream(encryptedPayload))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            decryptedResourceData = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            // Output the decrypted resource data
            Console.WriteLine("Decrypted Resource Data:");
            Console.WriteLine(decryptedResourceData);
        }
        else
        {
            Console.WriteLine("Signature verification failed. The payload may have been tampered with.");
            // Handle the tampered payload case (e.g., log, alert, or stop processing)
        }
    }
}

// Updated class definitions
public class SubscribedEvents
{
    [JsonPropertyName("value")]
    public List<EventItem> Value { get; set; }
}

public class EventItem
{
    [JsonPropertyName("subscriptionId")]
    public string SubscriptionId { get; set; }

    [JsonPropertyName("changeType")]
    public string ChangeType { get; set; }

    [JsonPropertyName("clientState")]
    public string ClientState { get; set; }

    [JsonPropertyName("subscriptionExpirationDateTime")]
    public string SubscriptionExpirationDateTime { get; set; }

    [JsonPropertyName("resource")]
    public string Resource { get; set; }

    [JsonPropertyName("resourceData")]
    public ResourceData ResourceData { get; set; }

    [JsonPropertyName("encryptedContent")]
    public EncryptedContent EncryptedContent { get; set; }

    [JsonPropertyName("tenantId")]
    public string TenantId { get; set; }
}

public class ResourceData
{
    [JsonPropertyName("id")]
    public string Id { get; set; }

    [JsonPropertyName("@odata.type")]
    public string OdataType { get; set; }

    [JsonPropertyName("@odata.id")]
    public string OdataId { get; set; }
}

public class EncryptedContent
{
    [JsonPropertyName("data")]
    public string Data { get; set; }

    [JsonPropertyName("dataSignature")]
    public string DataSignature { get; set; }

    [JsonPropertyName("dataKey")]
    public string DataKey { get; set; }

    [JsonPropertyName("encryptionCertificateId")]
    public string EncryptionCertificateId { get; set; }

    [JsonPropertyName("encryptionCertificateThumbprint")]
    public string EncryptionCertificateThumbprint { get; set; }
}
