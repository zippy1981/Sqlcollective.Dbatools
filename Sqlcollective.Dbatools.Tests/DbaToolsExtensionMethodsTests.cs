using System;
using NUnit.Framework;
using Sqlcollective.Dbatools.Utility;

namespace Sqlcollective.Dbatools.Tests
{
    [TestFixture]
    public class DbaToolsExtensionMethodsTests
    {
        [Test]
        public void TestGetBytes()
        {
            Assert.AreEqual(new byte[] {1, 0}, DbaPasswordHashVersion.Sql2000.GetBytes());
            Assert.AreEqual(new byte[] {2, 0}, DbaPasswordHashVersion.Sql2012.GetBytes());
        }
        [Test]
        public void TestGetBytesBadVersion()
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                delegate { ((DbaPasswordHashVersion) 3).GetBytes(); },
                "Cannot call GetBytes on an invalid password has version."
            );
        }


        [Test]
        public void TestCopyArray()
        {
            Assert.True((new[] {1, 2, 3}).EqualsArray(new[] {1, 2, 3}));
        }

        [Test]
        public void TestCopyArrayUnequalLengths()
        {
            Assert.False((new [] { 1, 2, 3}).EqualsArray(new[] { 1, 2  }));
        }

        [Test]
        public void TestCopyArrayUnequalValues()
        {
            Assert.False((new [] { 1, 2, 3}).EqualsArray(new[] { 1, 2, 4 }));
        }
    }
}