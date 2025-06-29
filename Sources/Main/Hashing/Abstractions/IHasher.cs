namespace DevOnBike.Heimdall.Hashing.Abstractions
{
    public interface IHasher
    {
        /// <summary>
        /// name of hash algorithm
        /// </summary>
        string Id { get; }

        /// <summary>
        /// Gets the size of the hash digest in bytes.
        /// </summary>
        int HashSizeInBytes { get; }

        /// <summary>
        /// Computes the hash of the provided data.
        /// </summary>
        /// <param name="source">The data to hash.</param>
        /// <returns>A byte array representing the computed hash digest.</returns>
        byte[] Hash(ReadOnlySpan<byte> source);

        /// <summary>
        /// Asynchronously computes the hash of a stream.
        /// </summary>
        /// <param name="source">The stream to hash.</param>
        /// <param name="cancellation">A token for cancelling the operation.</param>
        /// <returns>A task that represents the asynchronous hash operation, yielding a byte array with the computed hash digest.</returns>
        ValueTask<byte[]> HashAsync(Stream source, CancellationToken cancellation);
    }
}