using System;
using System.Collections.Generic;
using NUnit.Framework;

using Sqlcollective.Dbatools.Utility;

namespace Sqlcollective.Dbatools.Tests
{
    [TestFixture]
    public class DbaPasswordHashTests
    {
        private sealed class PasswordData
        {
            public string PlainText { get; }
            public string Hash { get; }

            public PasswordData(string plaintext, string hash)
            {
                PlainText = plaintext;
                Hash = hash;
            }
        }
        
        private IList<PasswordData> Passwords = new List<PasswordData>
        {
            new PasswordData("secretP@ssword", "020044A236AE0264C666A1403706613D91C40BC8264FCE7FB713BDF8770AD951503C95999AF3DBB53FD04A1785B86357EF09EA1E3403F6921D32249AF2C4E9DCB8F09BBC476C"),
            new PasswordData("zippy", "0100F440586023344450835A2B693974B79D93D9E08D9D451ADA1C74C460DA4C5371BC7970AF422C52F88784D002"),
            new PasswordData("ZIPPY", "0100BA51E20BFEC81D855CE4E97F102067F24B29943D92DAC328"),//"FEC81D855CE4E97F102067F24B29943D92DAC328"),
        };
        
        /// <seealso>
        ///     <cref>https://stackoverflow.com/a/26304129/95195</cref>
        /// </seealso>
        private byte[] HexadecimalStringToByteArray_BestEffort(string input)
        {
            var outputLength = input.Length / 2;
            var output = new byte[outputLength];
            var numeral = new char[2];
            for (var i = 0; i < outputLength; i++)
            {
                input.CopyTo(i * 2, numeral, 0, 2);
                output[i] = Convert.ToByte(new string(numeral), 16);
            }
            return output;
        }
        
        [Test]
        public void TestHashVerify()
        {
            foreach (var password in Passwords)
            {
                var hashBytes = HexadecimalStringToByteArray_BestEffort(password.Hash);
                var passwordHash = new DbaPasswordHash(hashBytes);
                var generatedHash = DbaPasswordHash.GenerateHash(password.PlainText, passwordHash.Salt, passwordHash.HashVersion, passwordHash.RawHashUpperCase != null);
                Assert.AreEqual(hashBytes, generatedHash, $"Password hash for {password.PlainText} is incorrect.");
                Assert.True(passwordHash.VerifyPassword(password.PlainText), $"Verifying password {password.PlainText} against hash failed.");
            }
        }

        [Test]
        public void TestHashVerifyFail()
        {
            var password = Passwords[0];
            var hashBytes = HexadecimalStringToByteArray_BestEffort(password.Hash);
            var passwordHash = new DbaPasswordHash(hashBytes);
            var generatedHash = DbaPasswordHash.GenerateHash("Not the password", passwordHash.Salt);
            Assert.AreNotEqual(hashBytes, generatedHash);
            Assert.False(passwordHash.VerifyPassword("Not the Password"));
        }

        [Test]
        public void TestIncorrectVersion()
        {
            var hashBytes = HexadecimalStringToByteArray_BestEffort("0300");
            Assert.Throws<ArgumentOutOfRangeException>(
                delegate { new DbaPasswordHash(hashBytes); },
                "Incorrect password version of 3"
            );
        }

        [Test]
        public void TestGenerateHashIncorrectVersion()
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                delegate { DbaPasswordHash.GenerateHash("password", version: (DbaPasswordHashVersion)7); },
                "Unsupported password version of 7"
            );
        }

        [Test]
        public void TestInCorrectPasswordLength()
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                delegate { new DbaPasswordHash(HexadecimalStringToByteArray_BestEffort("0200FFFFFFFFFF")); },
                $"Password hash for a Sql Server 2012+ password must be {DbaPasswordHash.Sha1PasswordHashLength} bytes long"
            );
            Assert.Throws<ArgumentOutOfRangeException>(
                delegate { new DbaPasswordHash(HexadecimalStringToByteArray_BestEffort("0100FFFFFFFFFF")); },
                $"Password hash for a Sql Server 2005 to 2008 password must be {DbaPasswordHash.Sha1PasswordHashLength} bytes long"
            );
        }

        /// <summary>
        /// We don't actually randomly generate a salt in the main test so do that here.
        /// </summary>
        [Test]
        public void TestPassworWithRandomHash()
        {
            var password = "secretPassword";
            var passwordHash = DbaPasswordHash.GenerateHash(password);
            var passwordHash2000 = DbaPasswordHash.GenerateHash(password, version: DbaPasswordHashVersion.Sql2000);
            Assert.AreNotEqual(passwordHash2000, passwordHash);
            var hashObj = new DbaPasswordHash(passwordHash);
            var hashObj2000 = new DbaPasswordHash(passwordHash2000);
            Assert.True(hashObj.VerifyPassword(password));
            Assert.True(hashObj2000.VerifyPassword(password));
        }

        [Test]
        public void TestCaseInsensitivePasswordPasswordHash()
        {
            var password = "s3cretP@ssword";
            var hash = DbaPasswordHash.GenerateHash(password, version: DbaPasswordHashVersion.Sql2000, caseInsensitive: true);
            Assert.AreEqual(DbaPasswordHash.Sha1CaseInsensitivePasswordHashLength, hash.Length);
            var hashObj = new DbaPasswordHash(hash);
            Assert.True(hashObj.VerifyPassword(password));
            Assert.True(hashObj.VerifyPassword(password.ToLower()));
            Assert.True(hashObj.VerifyPassword(password.ToLowerInvariant()));
            Assert.True(hashObj.VerifyPassword(password.ToUpper()));
            Assert.True(hashObj.VerifyPassword(password.ToUpperInvariant()));
        }

        /// <summary>
        /// Assert that we can't create a SQL Server 2012+ style password hash that is case insensitive.
        /// </summary>
        [Test]
        public void TestCaseInsensitiveV2PasswordException()
        {
            var password = "secretPassword";
            Assert.Throws<ArgumentException>(
                delegate { DbaPasswordHash.GenerateHash(password, version: DbaPasswordHashVersion.Sql2012, caseInsensitive: true); },
                "Only Sql Server 2000 passwords can be case insensitive."
            );
            

        }
    }
}