using System;
using System.IO;
using System.Xml.Linq;
using Xunit;

namespace aaa
{
    public class XDocumentFixerRecursiveTests
    {
        /// <summary>
        /// A helper method to compare two XML strings for semantic equality,
        /// ignoring formatting differences.
        /// </summary>
        private void AssertXmlEquals(string expected, string actual)
        {
            try
            {
                var expectedDoc = XDocument.Parse(expected, LoadOptions.PreserveWhitespace);
                var actualDoc = XDocument.Parse(actual, LoadOptions.PreserveWhitespace);

                Assert.True(XNode.DeepEquals(expectedDoc, actualDoc),
                    $"XML should be semantically equal.\nExpected:\n{expectedDoc}\nActual:\n{actualDoc}");
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to parse or compare XML strings.\nExpected:\n{expected}\nActual:\n{actual}", ex);
            }
        }

        [Fact]
        public void FixXmlString_WithMixedContentErrors_FixesCorrectly()
        {
            // Arrange
            var brokenXml = @"<?xml version=""1.0"" encoding=""utf-8""?>
<n:root xmlns:n=""uri:ns"">
    <n:item id=""value&id"">Some text with an illegal char &#2; and an ampersand &.</n:item>
    <n:valid>This is &lt;valid&gt;.</n:valid>
    <n:empty attr=""value with bad char &#3;"" />
</n:root>";

            var expectedXml = @"<?xml version=""1.0"" encoding=""utf-8""?>
<n:root xmlns:n=""uri:ns"">
    <n:item id=""value&amp;id"">Some text with an illegal char  and an ampersand &amp;.</n:item>
    <n:valid>This is &lt;valid&gt;.</n:valid>
    <n:empty attr=""value with bad char "" />
</n:root>";

            // Act
            string result = XDocumentFixer.FixXmlString(brokenXml);

            // Assert
            AssertXmlEquals(expectedXml, result);
        }

        [Theory]
        [InlineData("<item>Bad char: \u0001</item>", "<item>Bad char: </item>")]
        [InlineData("<item attr='Bad char: \u0008'></item>", "<item attr=\"Bad char: \"></item>")]
        [InlineData("<item>Bad & Ampersand</item>", "<item>Bad &amp; Ampersand</item>")]
        [InlineData("<item attr='Bad & Ampersand'></item>", "<item attr=\"Bad &amp; Ampersand\"></item>")]
        [InlineData("<item>This is &lt;OK&gt;.</item>", "<item>This is &lt;OK&gt;.</item>")]
        [InlineData("<item>Ends with ampersand &</item>", "<item>Ends with ampersand &amp;</item>")]
        public void FixXmlString_WithSpecificContentErrors_FixesAsExpected(string broken, string expected)
        {
            // Act
            string result = XDocumentFixer.FixXmlString(broken);

            // Assert
            AssertXmlEquals($"<root>{expected}</root>", $"<root>{result}</root>");
        }

        [Fact]
        public void FixXmlString_WithCDataSection_PreservesCData()
        {
            // Arrange
            var brokenXml = "<item><![CDATA[This has < & > and even \u0001 which are all legal here.]]></item>";

            // Act
            string result = XDocumentFixer.FixXmlString(brokenXml);

            // Assert: The fixer should not change a CDATA section at all.
            AssertXmlEquals(brokenXml, result);
        }

        [Fact]
        public void FixXmlString_WithEmptyStringInput_ReturnsEmptyString()
        {
            // Act
            string result = XDocumentFixer.FixXmlString("");

            // Assert
            Assert.Empty(result);
        }

        [Fact]
        public void FixXmlString_WithNullInput_ReturnsNull()
        {
            // Act
            string result = XDocumentFixer.FixXmlString(null);

            // Assert
            Assert.Null(result);
        }
    }
}

