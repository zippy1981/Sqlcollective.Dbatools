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
            new PasswordData("zippy", "0100F440586023344450835A2B693974B79D93D9E08D9D451ADA"),//"1C74C460DA4C5371BC7970AF422C52F88784D002"),
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
                var generatedHash = DbaPasswordHash.GenerateHash(password.PlainText, passwordHash.Salt, passwordHash.HashVersion);
                Assert.AreEqual(hashBytes, generatedHash, $"Password hash for {password.PlainText} is incorrect.");
                Assert.True(passwordHash.VerifyPassword(password.PlainText), $"Verifying password ${password} against hash failed.");
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
        
        /*
         * TODO: Tests for these:
         *     https://sqlcommunity.slack.com/archives/C1M2WEASG/p1496751699689835
         *    https://sqlcommunity.slack.com/files/cl/F5P75QJ3V/login_zippy_password_zippy.txt
         */
    }
}