package platform

// Test vector of draft-novak-lamps-tacra-est, Appendix A, in the order of TACRA Section 4.5 (master 912bd50, 30 September
// 2026): the enrollment of SEV-SNP run 20260930T172002Z, where SHA-512(binding_input) equals REPORT_DATA of the hardware
// report (github.com/nikolaichuk7/tacra-est, commit 5661be5).
const (
	tvHandleHex  = "f8170e6438729e1e3ded60c7c8b220716b7138f9a7e6250c569f1548790ee25f"
	tvRRPID      = "https://ca1.tacra.example"
	tvTarget     = "https://db.tacra.example"
	tvSubjectHex = "3081dc3081830201003021311f301d06035504030c16776f726b6c6f61642e74616372612e6578616d706c653059301306072a8648ce3d020106082a8648ce3d0301070342000458f74deb3089c1ba23a2a630a94812f503377fa33d252cd5b2a287fefa40bca353ff2671caa8565de5cc5d221d2a61e5610f9748224dd4a210c82bdfa329d7c2a000300a06082a8648ce3d0403020348003045022100a214dc7a98c6dd8c702a38cc2acabbf0fc7391491a546720f69bf29fdbe7056202205708ed7cf3fc25d8f2501639a589a69be2aa8468f97ff4008d3ea124147a0347"
	tvDigestHex  = "c5d8f3e4a93130e864df61ef1bf940223d8d891fa668d21aceffb34f20473065c3cf80a64ccd0c8c5a60717a5d25cb8b2131bf2e51be88f7beadba6bb181d4ca"
)
