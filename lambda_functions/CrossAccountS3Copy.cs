using Amazon.Lambda.Core;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using System;
using System.IO;
using System.Threading.Tasks;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace CrossAccountS3Copy
{
    public class Function
    {
        private readonly IAmazonS3 _s3Client;
        private readonly IAmazonSecurityTokenService _stsClient;

        public Function()
        {
            _s3Client = new AmazonS3Client();
            _stsClient = new AmazonSecurityTokenServiceClient();
        }

        public async Task<string> FunctionHandler(S3CopyRequest request, ILambdaContext context)
        {
            try
            {
                // Assume role in AccountB
                var assumeRoleResponse = await _stsClient.AssumeRoleAsync(new AssumeRoleRequest
                {
                    RoleArn = request.AccountBRoleArn,
                    RoleSessionName = "CrossAccountS3Copy"
                });

                // Create S3 client with assumed role credentials for AccountB
                var accountBS3Client = new AmazonS3Client(
                    assumeRoleResponse.Credentials.AccessKeyId,
                    assumeRoleResponse.Credentials.SecretAccessKey,
                    assumeRoleResponse.Credentials.SessionToken
                );

                // Get object from AccountB bucket
                var getObjectResponse = await accountBS3Client.GetObjectAsync(new GetObjectRequest
                {
                    BucketName = request.AccountBBucket,
                    Key = request.ObjectKey
                });

                // Copy object to AccountA bucket using Lambda's own credentials
                await _s3Client.PutObjectAsync(new PutObjectRequest
                {
                    BucketName = request.AccountABucket,
                    Key = request.ObjectKey,
                    InputStream = getObjectResponse.ResponseStream,
                    ContentType = getObjectResponse.Headers.ContentType
                });

                return $"Successfully copied {request.ObjectKey} from {request.AccountBBucket} to {request.AccountABucket}";
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error: {ex.Message}");
                throw;
            }
        }
    }

    public class S3CopyRequest
    {
        public string AccountBRoleArn { get; set; }
        public string AccountBBucket { get; set; }
        public string AccountABucket { get; set; }
        public string ObjectKey { get; set; }
    }
}