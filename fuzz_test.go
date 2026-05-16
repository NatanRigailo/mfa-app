package main

import "testing"

func FuzzExtractSecretFromURI(f *testing.F) {
	f.Add("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")
	f.Add("otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP")
	f.Add("https://example.com")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		extractSecretFromURI(input)
	})
}

func FuzzSanitizeSecret(f *testing.F) {
	f.Add("JBSWY3DPEHPK3PXP")
	f.Add("jbswy3dpehpk3pxp")
	f.Add("invalid!@#")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		sanitizeSecret(input)
	})
}

func FuzzVerifyMAC(f *testing.F) {
	key := []byte("fuzz-key")
	f.Add(signMAC(key, []byte(`{"e":false,"c":"token"}`)))
	f.Add("")
	f.Add(".")
	f.Add("nodot")

	f.Fuzz(func(t *testing.T, value string) {
		verifyMAC(key, value)
	})
}
