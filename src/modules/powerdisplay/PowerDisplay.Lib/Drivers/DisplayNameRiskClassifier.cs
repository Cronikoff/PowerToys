// Copyright (c) Microsoft Corporation
// The Microsoft Corporation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace PowerDisplay.Common.Drivers
{
    /// <summary>
    /// Classifies display device names as suspicious or blocked based on keyword matching.
    /// Pure-function helper — no side effects, no dependencies.
    /// </summary>
    public static class DisplayNameRiskClassifier
    {
        /// <summary>
        /// Returns <see langword="true"/> when the display name contains a keyword
        /// that indicates a virtual or remote-desktop adapter which may not behave
        /// like a physical monitor (e.g. RDP, indirect display, Miracast sink).
        /// These devices are not blocked, but callers may choose to warn the user.
        /// </summary>
        public static bool IsSuspicious(string? displayName)
        {
            if (string.IsNullOrWhiteSpace(displayName))
            {
                return false;
            }

            return displayName.Contains("virtual", System.StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("remote", System.StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("rdp", System.StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("indirect", System.StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Returns <see langword="true"/> when the display name contains a keyword
        /// that is strongly associated with malicious software.
        /// Callers should refuse to process devices whose names are flagged here.
        /// </summary>
        public static bool IsBlocked(string? displayName)
        {
            if (string.IsNullOrWhiteSpace(displayName))
            {
                return false;
            }

            return displayName.Contains("malware", System.StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("rootkit", System.StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("inject", System.StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("spyware", System.StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("keylog", System.StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("mitm", System.StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("man-in-the-middle", System.StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("exploit", System.StringComparison.OrdinalIgnoreCase);
        }
    }
}
