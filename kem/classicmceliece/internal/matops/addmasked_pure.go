package matops

// AddMasked sets dst[i] ^= src[i] & mask for every byte in the shorter of dst
// and src. This pure-Go backport always processes the complete slice and never
// branches on the mask value.
func AddMasked(dst, src []byte, mask byte) {
	addMaskedGeneric(dst, src, mask)
}
