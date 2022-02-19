namespace SharpSCCM
{
    public static class Helpers
    {
        public static bool IsUnicode(byte[] bytes)
        {
            // Helper that uses IsTextUnicode() API call to determine if a byte array is likely unicode text
            Interop.IsTextUnicodeFlags flags = Interop.IsTextUnicodeFlags.IS_TEXT_UNICODE_STATISTICS;
            return Interop.IsTextUnicode(bytes, bytes.Length, ref flags);
        }
    }
}