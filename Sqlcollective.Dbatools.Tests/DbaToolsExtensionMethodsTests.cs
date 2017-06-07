using NUnit.Framework;

namespace Sqlcollective.Dbatools.Tests
{
    [TestFixture]
    public class DbaToolsExtensionMethodsTests
    {
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