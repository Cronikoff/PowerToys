// Copyright (c) Microsoft Corporation
// The Microsoft Corporation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using PowerDisplay.Common.Drivers;

namespace PowerDisplay.UnitTests;

[TestClass]
public class DisplayNameRiskClassifierTests
{
    // -------------------------------------------------------------------------
    // IsSuspicious
    // -------------------------------------------------------------------------

    [DataTestMethod]
    [DataRow(null, false, DisplayName = "null is not suspicious")]
    [DataRow("", false, DisplayName = "empty string is not suspicious")]
    [DataRow("   ", false, DisplayName = "whitespace-only is not suspicious")]
    [DataRow("Dell U2722D", false, DisplayName = "normal monitor name is not suspicious")]
    [DataRow("LG ULTRAFINE 4K", false, DisplayName = "normal uppercase name is not suspicious")]
    [DataRow("VirtualBox Display", true, DisplayName = "contains 'virtual'")]
    [DataRow("VIRTUAL MONITOR", true, DisplayName = "uppercase VIRTUAL is suspicious")]
    [DataRow("Remote Desktop Mirror", true, DisplayName = "contains 'remote'")]
    [DataRow("RDP Display", true, DisplayName = "contains 'rdp'")]
    [DataRow("rdp-session-0", true, DisplayName = "lowercase rdp is suspicious")]
    [DataRow("Indirect Display Adapter", true, DisplayName = "contains 'indirect'")]
    [DataRow("INDIRECT_VIRTUAL_ADAPTER", true, DisplayName = "uppercase INDIRECT is suspicious")]
    public void IsSuspicious_ReturnsExpectedResult(string? displayName, bool expected)
    {
        Assert.AreEqual(expected, DisplayNameRiskClassifier.IsSuspicious(displayName));
    }

    // -------------------------------------------------------------------------
    // IsBlocked
    // -------------------------------------------------------------------------

    [DataTestMethod]
    [DataRow(null, false, DisplayName = "null is not blocked")]
    [DataRow("", false, DisplayName = "empty string is not blocked")]
    [DataRow("   ", false, DisplayName = "whitespace-only is not blocked")]
    [DataRow("Samsung C49RG9x", false, DisplayName = "normal monitor name is not blocked")]
    [DataRow("malware-display", true, DisplayName = "contains 'malware'")]
    [DataRow("MALWARE_DRIVER", true, DisplayName = "uppercase MALWARE is blocked")]
    [DataRow("rootkit-display", true, DisplayName = "contains 'rootkit'")]
    [DataRow("inject-virtual-sink", true, DisplayName = "contains 'inject'")]
    [DataRow("INJECT_DISPLAY", true, DisplayName = "uppercase INJECT is blocked")]
    [DataRow("spyware-cam-output", true, DisplayName = "contains 'spyware'")]
    [DataRow("keylog-capture-device", true, DisplayName = "contains 'keylog'")]
    [DataRow("KEYLOG_DISPLAY", true, DisplayName = "uppercase KEYLOG is blocked")]
    [DataRow("mitm-proxy-display", true, DisplayName = "contains 'mitm'")]
    [DataRow("man-in-the-middle display", true, DisplayName = "contains 'man-in-the-middle'")]
    [DataRow("Man-In-The-Middle Monitor", true, DisplayName = "mixed-case man-in-the-middle is blocked")]
    [DataRow("exploit-framebuffer", true, DisplayName = "contains 'exploit'")]
    [DataRow("EXPLOIT_DISPLAY", true, DisplayName = "uppercase EXPLOIT is blocked")]
    public void IsBlocked_ReturnsExpectedResult(string? displayName, bool expected)
    {
        Assert.AreEqual(expected, DisplayNameRiskClassifier.IsBlocked(displayName));
    }

    // -------------------------------------------------------------------------
    // Relationship: blocked names are not necessarily suspicious and vice-versa
    // -------------------------------------------------------------------------

    [TestMethod]
    public void BlockedName_IsNotAutomaticallySuspicious()
    {
        // "malware-display" is blocked but does not contain a "suspicious" keyword
        Assert.IsTrue(DisplayNameRiskClassifier.IsBlocked("malware-display"));
        Assert.IsFalse(DisplayNameRiskClassifier.IsSuspicious("malware-display"));
    }

    [TestMethod]
    public void SuspiciousName_IsNotAutomaticallyBlocked()
    {
        // "VirtualBox Display" is suspicious but is not blocked
        Assert.IsTrue(DisplayNameRiskClassifier.IsSuspicious("VirtualBox Display"));
        Assert.IsFalse(DisplayNameRiskClassifier.IsBlocked("VirtualBox Display"));
    }
}
