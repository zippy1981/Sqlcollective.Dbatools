using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Sqlcollective.Dbatools.Utility
{   
    /// <summary>
    /// Information about a sql server password hash
    /// </summary>
    /// <seealso cref="http://sqlity.net/en/2460/sql-password-hash/"/>
    public sealed class DbaPasswordHash {
        
        /// <summary>Length in bytes of the salt.</summary>
        public const int SaltLength = 4;
        /// <summary>Offset position of the salt in the raw hash.</summary>
        public const int SaltOffset = 2;
        /// <summary>Offset position of the hash in the raw hash.</summary>
        public const int HashOffset = 6;
        /// <summary>Length in bytes of a SHA1 hash</summary>
        public const int Sha1Length = 20;
        /// <summary>Length in bytes of a SHA256 hash</summary>
        public const int Sha512Length = 64;
        /// <summary>Length in bytes of a complete SHA1 password hash</summary>
        public const int Sha1PasswordHashLength = 26;
        /// <summary>Length in bytes of a complete case insensitive SHA1 password hash</summary>
        public const int Sha1CaseInsensitivePasswordHashLength = 46;
        /// <summary>Length in bytes of a complete SHA256 password hash</summary>
        public const int Sha512PasswordHashLength = 70;

        private static readonly SHA1 Sha1;
        private static readonly SHA512 Sha512;
        private static readonly RNGCryptoServiceProvider RngCryptoServiceProvider;
        
        public DbaPasswordHashVersion HashVersion { get; }

        public uint Salt { get; }
    
        public byte[] Hash { get; }
    
        public byte[] UpperCaseHash { get; }
        
        public byte[] RawHash { get;  }
        
        public byte[] RawHashUpperCase { get;  }

        /// <remarks>TODO: dynamically use an unmanaged library if its faster.</remarks>
        /// <seealso cref="https://msdn.microsoft.com/en-us/library/system.security.cryptography.sha1managed(v=vs.110).aspx"/>
        static DbaPasswordHash()
        {
            Sha1 = new SHA1Managed();
            Sha512 = new SHA512Managed();
            RngCryptoServiceProvider = new RNGCryptoServiceProvider();
        }
        
        public DbaPasswordHash(byte[] rawHash)
        {
            HashVersion = (DbaPasswordHashVersion) BitConverter.ToUInt16(rawHash, 0);
            switch (HashVersion)
            {
                case DbaPasswordHashVersion.Sql2005:
                    //TODO: deal with SQL Server 2000 case insensitive format
                    if (rawHash.Length != Sha1PasswordHashLength && rawHash.Length != Sha1CaseInsensitivePasswordHashLength)
                    {
                        var msg =
                            $"Password hash for a Sql Server 2005 to 2008 password must be {Sha1PasswordHashLength}  or {Sha1CaseInsensitivePasswordHashLength}  bytes long";
                        throw new ArgumentOutOfRangeException
                            (nameof(rawHash), msg);
                    }
                    RawHash = new byte[Sha1PasswordHashLength];
                    Array.Copy(rawHash, 0, RawHash, 0, Sha1PasswordHashLength);
                    Hash = new byte[Sha1Length];
                    Array.Copy(rawHash, HashOffset, Hash, 0, Sha1Length);
                    if (rawHash.Length == Sha1CaseInsensitivePasswordHashLength)
                    {
                        UpperCaseHash = new byte[Sha1Length];
                        Array.Copy(rawHash, Sha1PasswordHashLength, UpperCaseHash, 0, Sha1Length);
                    }
                    break;
                case DbaPasswordHashVersion.Sql2012:
                    RawHash = rawHash;
                    Hash = new byte[Sha512Length];
                    if (rawHash.Length != Sha512PasswordHashLength)
                    {
                        var msg =
                            $"Password hash for a Sql Server 2012+ password must be {Sha512PasswordHashLength} bytes long";
                        throw new ArgumentOutOfRangeException
                            (nameof(rawHash), msg);
                    }
                    Array.Copy(rawHash, HashOffset, Hash, 0, Sha512Length);
                    break;
                default:
                    throw new ArgumentOutOfRangeException($"Incorrect password version of {HashVersion}.", nameof(rawHash));
            }
            Salt = BitConverter.ToUInt32(rawHash, SaltOffset);
        }

        public static byte[]  GenerateHash
            (string password, UInt32? salt = null,
             DbaPasswordHashVersion version = DbaPasswordHashVersion.Sql2016,
             bool caseInsensitive = false)
        {
            var saltBytes = new byte[4];
            if (salt == null)
            {
                RngCryptoServiceProvider.GetNonZeroBytes(saltBytes);
                salt = BitConverter.ToUInt32(saltBytes, 0);
            }
            else
            {
                saltBytes = BitConverter.GetBytes(salt.Value);
            }
            var passwordBytes = Encoding.Unicode.GetBytes(password).Concat(saltBytes).ToArray();
            Debug.WriteLine($"password bytes with salt: {BitConverter.ToString(passwordBytes)}");
            byte[] hash;
            switch (version)
            {
                case DbaPasswordHashVersion.Sql2005:
                    hash = Sha1.ComputeHash(passwordBytes);
                    if (caseInsensitive)
                    {
                        var upperCasePasswordBytes = Encoding.Unicode.GetBytes(password.ToUpper()).Concat(saltBytes).ToArray();
                        Debug.WriteLine($"uppercase password bytes with salt: {BitConverter.ToString(upperCasePasswordBytes)}");
                        hash = hash.Concat(Sha1.ComputeHash(upperCasePasswordBytes)).ToArray();
                    }
                    break;
                case DbaPasswordHashVersion.Sql2012:
                    if (caseInsensitive)
                    {
                        throw new ArgumentException("Only Sql Server 2000 passwords can be case insensitive.");
                    }
                    hash = Sha512.ComputeHash(passwordBytes);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(version), $"Unsupported password version of {(uint) version}");
            }
            var completeHash = version.GetBytes().Concat(saltBytes).Concat(hash).ToArray();
            Debug.WriteLine($"completed hash: {BitConverter.ToString(completeHash)}");
            return completeHash;
        }

        public bool VerifyPassword(string password)
        {
            var generated = GenerateHash(password, Salt, HashVersion);
            return generated.EqualsArray(RawHash);
        }
    }
}