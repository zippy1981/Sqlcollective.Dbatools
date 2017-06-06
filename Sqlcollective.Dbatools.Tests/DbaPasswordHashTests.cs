using System;

using NUnit.Framework;

using Sqlcollective.Dbatools.Utility;

namespace Sqlcollective.Dbatools.Tests
{
    [TestFixture]
    public class DbaPasswordHashTests
    {
        private const string Hash = "020044A236AE0264C666A1403706613D91C40BC8264FCE7FB713BDF8770AD951503C95999AF3DBB53FD04A1785B86357EF09EA1E3403F6921D32249AF2C4E9DCB8F09BBC476C";
        private const string Password = "secretP@ssword";

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
            var hashBytes = HexadecimalStringToByteArray_BestEffort(Hash);
            var passwordHash = new DbaPasswordHash(hashBytes);
            var generatedHash = DbaPasswordHash.GenerateHash(Password, passwordHash.Salt);
            Assert.AreEqual(hashBytes, generatedHash);
            Assert.True(passwordHash.VerifyPassword(Password));
        }
        
        [Test]
        public void TestHashVerifyFail()
        {
            var hashBytes = HexadecimalStringToByteArray_BestEffort(Hash);
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